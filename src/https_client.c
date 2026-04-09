#include <ares.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ev.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns_server.h"
#include "https_client.h"
#include "logging.h"
#include "options.h"
#include "stat.h"

#define DOH_CONTENT_TYPE "application/dns-message"
enum {
DOH_MAX_RESPONSE_SIZE = 65535
};

// Fallback DNS support
static const char *fallback_dns_servers = NULL;
static int use_fallback = 0;

// the following macros require to have ctx pointer to https_fetch_ctx structure
// else: compilation failure will occur
#define LOG_REQ(level, format, args...) LOG(level, "%04hX: " format, ctx->id, ## args)
#define DLOG_REQ(format, args...) DLOG("%04hX: " format, ctx->id, ## args)
#define ILOG_REQ(format, args...) ILOG("%04hX: " format, ctx->id, ## args)
#define WLOG_REQ(format, args...) WLOG("%04hX: " format, ctx->id, ## args)
#define ELOG_REQ(format, args...) ELOG("%04hX: " format, ctx->id, ## args)
#define FLOG_REQ(format, args...) FLOG("%04hX: " format, ctx->id, ## args)

#define ASSERT_CURL_MULTI_SETOPT(curlm, option, param) \
  do { \
    CURLMcode code = curl_multi_setopt((curlm), (option), (param)); \
    if (code != CURLM_OK) { \
      FLOG(#option " error %d: %s", code, curl_multi_strerror(code)); \
    } \
  } while(0);

#define ASSERT_CURL_EASY_SETOPT(ctx, option, param) \
  do { \
    CURLcode code = curl_easy_setopt((ctx)->curl, (option), (param)); \
    if (code != CURLE_OK) { \
      FLOG_REQ(#option " error %d: %s", code, curl_easy_strerror(code)); \
    } \
  } while(0);

#define GET_PTR(type, var_name, from) \
  type *var_name = (type *)(from); \
  if ((var_name) == NULL) { \
    FLOG("Unexpected NULL pointer for " #var_name "(" #type ")"); \
  }

typedef struct {
    int block_private;   // RFC1918 + IPv6 ULA(fc00::/7) 过滤私有地址（通常只在内网可路由，公网不可达）
    int block_cgnat;     // 100.64.0.0/10 过滤 CGNAT 地址段（运营商级 NAT 内部用地址）
    int block_testnet;   // 192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32 过滤文档/示例用地址（专门留给教程、RFC 文档举例，不应该出现在真实 DNS 解析结果里）
} ip_filter_cfg_t;

static int ipv4_in_cidr_u32(uint32_t ip, uint32_t net, uint32_t mask) {
    return (ip & mask) == (net & mask);
}

/* 返回1=应过滤(无效/不接受), 0=接受 */
static int should_filter_dns_ip(const char *s, const ip_filter_cfg_t *cfg) {
    if (!s || !*s) {
        DLOG("IP validation: NULL or empty string -> FILTER");
        return 1;
    }

    struct in_addr a4;
    struct in6_addr a6;
    char reason[128] = "";

    /* IPv4 */
    if (inet_pton(AF_INET, s, &a4) == 1) {
        uint32_t ip = ntohl(a4.s_addr);
        uint8_t a = (ip >> 24) & 0xFF;
        uint8_t b = (ip >> 16) & 0xFF;
        uint8_t c = (ip >> 8) & 0xFF;
        uint8_t d = ip & 0xFF;

        /* 必过滤：unspecified/loopback/linklocal/multicast/broadcast/reserved */
        if (ipv4_in_cidr_u32(ip, 0x00000000u, 0xFF000000u)) {
            snprintf(reason, sizeof(reason), "0.0.0.0/8 (unspecified)");
            goto filter;
        }
        if (ipv4_in_cidr_u32(ip, 0x7F000000u, 0xFF000000u)) {
            snprintf(reason, sizeof(reason), "127.0.0.0/8 (loopback)");
            goto filter;
        }
        if (ipv4_in_cidr_u32(ip, 0xA9FE0000u, 0xFFFF0000u)) {
            snprintf(reason, sizeof(reason), "169.254.0.0/16 (link-local)");
            goto filter;
        }
        if (ipv4_in_cidr_u32(ip, 0xE0000000u, 0xF0000000u)) {
            snprintf(reason, sizeof(reason), "224.0.0.0/4 (multicast)");
            goto filter;
        }
        if (ip == 0xFFFFFFFFu) {
            snprintf(reason, sizeof(reason), "255.255.255.255 (broadcast)");
            goto filter;
        }
        if (ipv4_in_cidr_u32(ip, 0xF0000000u, 0xF0000000u)) {
            snprintf(reason, sizeof(reason), "240.0.0.0/4 (reserved)");
            goto filter;
        }

        if (cfg && cfg->block_private) {
            if (ipv4_in_cidr_u32(ip, 0x0A000000u, 0xFF000000u)) {
                snprintf(reason, sizeof(reason), "10.0.0.0/8 (private)");
                goto filter;
            }
            if (ipv4_in_cidr_u32(ip, 0xAC100000u, 0xFFF00000u)) {
                snprintf(reason, sizeof(reason), "172.16.0.0/12 (private)");
                goto filter;
            }
            if (ipv4_in_cidr_u32(ip, 0xC0A80000u, 0xFFFF0000u)) {
                snprintf(reason, sizeof(reason), "192.168.0.0/16 (private)");
                goto filter;
            }
        }

        if (cfg && cfg->block_cgnat) {
            if (ipv4_in_cidr_u32(ip, 0x64400000u, 0xFFC00000u)) {
                snprintf(reason, sizeof(reason), "100.64.0.0/10 (CGNAT)");
                goto filter;
            }
        }

        if (cfg && cfg->block_testnet) {
            if (ipv4_in_cidr_u32(ip, 0xC0000200u, 0xFFFFFF00u)) {
                snprintf(reason, sizeof(reason), "192.0.2.0/24 (TEST-NET-1)");
                goto filter;
            }
            if (ipv4_in_cidr_u32(ip, 0xC6336400u, 0xFFFFFF00u)) {
                snprintf(reason, sizeof(reason), "198.51.100.0/24 (TEST-NET-2)");
                goto filter;
            }
            if (ipv4_in_cidr_u32(ip, 0xCB007100u, 0xFFFFFF00u)) {
                snprintf(reason, sizeof(reason), "203.0.113.0/24 (TEST-NET-3)");
                goto filter;
            }
        }

        DLOG("IP validation: %u.%u.%u.%u -> ALLOW (public/routable)", a, b, c, d);
        return 0;

    filter:
        DLOG("IP validation: %u.%u.%u.%u -> FILTER (%s)", a, b, c, d, reason);
        return 1;
    }

    /* IPv6 */
    if (inet_pton(AF_INET6, s, &a6) == 1) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &a6, ip_str, sizeof(ip_str));

        /* 必过滤：unspecified/loopback/linklocal/multicast */
        if (IN6_IS_ADDR_UNSPECIFIED(&a6)) {
            DLOG("IP validation: %s -> FILTER (:: unspecified)", ip_str);
            return 1;
        }
        if (IN6_IS_ADDR_LOOPBACK(&a6)) {
            DLOG("IP validation: %s -> FILTER (::1 loopback)", ip_str);
            return 1;
        }
        if (a6.s6_addr[0] == 0xFF) {
            DLOG("IP validation: %s -> FILTER (ff00::/8 multicast)", ip_str);
            return 1;
        }
        if (a6.s6_addr[0] == 0xFE && (a6.s6_addr[1] & 0xC0) == 0x80) {
            DLOG("IP validation: %s -> FILTER (fe80::/10 link-local)", ip_str);
            return 1;
        }

        if (cfg && cfg->block_private) {
            if ((a6.s6_addr[0] & 0xFE) == 0xFC) {
                DLOG("IP validation: %s -> FILTER (fc00::/7 ULA)", ip_str);
                return 1;
            }
        }

        if (cfg && cfg->block_testnet) {
            if (a6.s6_addr[0] == 0x20 && a6.s6_addr[1] == 0x01 &&
                a6.s6_addr[2] == 0x0D && a6.s6_addr[3] == 0xB8) {
                DLOG("IP validation: %s -> FILTER (2001:db8::/32 documentation)", ip_str);
                return 1;
            }
        }

        DLOG("IP validation: %s -> ALLOW (public/routable)", ip_str);
        return 0;
    }

    /* 不是IP字面量：对“服务器返回的IP”来说应当视为无效 */
    DLOG("IP validation: '%s' -> FILTER (not an IP address)", s);
    return 1;
}

// 检查DNS响应中是否包含无效IP地址
static int dns_response_has_invalid_ips(const uint8_t *response, size_t response_len) {
    if (!response || response_len < DNS_HEADER_LENGTH) {
        return 0;
    }

    ares_dns_record_t *dnsrec = NULL;
    ares_status_t status = ares_dns_parse(response, response_len, 0, &dnsrec);
    if (status != ARES_SUCCESS) {
        DLOG("Failed to parse DNS response for IP validation: %s", ares_strerror((int)status));
        return 0;
    }

    const uint16_t tx_id = ares_dns_record_get_id(dnsrec);
    int has_invalid = 0;
    int a_record_count = 0;
    int aaaa_record_count = 0;

    // 配置过滤选项（可以将来从命令行配置）
    ip_filter_cfg_t cfg = {
        .block_private = 1,   // 过滤私有地址
        .block_cgnat = 1,     // 过滤CGNAT
        .block_testnet = 1    // 过滤测试网络
    };

    // 检查ANSWER section中的记录
    size_t answer_count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    DLOG("%04hX: Total answer records: %zu", tx_id, answer_count);

    for (size_t i = 0; i < answer_count; i++) {
        const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, i);
        ares_dns_rec_type_t type = ares_dns_rr_get_type(rr);
        const char *rr_name = ares_dns_rr_get_name(rr);

        // 获取该记录类型的所有keys
        size_t keys_cnt = 0;
        const ares_dns_rr_key_t *keys = ares_dns_rr_get_keys(type, &keys_cnt);

        DLOG("%04hX: Record %zu - type: %d (%s), name: %s, keys: %zu",
             tx_id, i, type, ares_dns_rec_type_tostr(type),
             rr_name ? rr_name : "unknown", keys_cnt);

        // 遍历所有keys，查找IP地址类型的数据
        for (size_t k = 0; k < keys_cnt; k++) {
            ares_dns_datatype_t datatype = ares_dns_rr_key_datatype(keys[k]);

            if (datatype == ARES_DATATYPE_INADDR) {
                a_record_count++;
                const struct in_addr *addr = ares_dns_rr_get_addr(rr, keys[k]);
                if (addr) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
                    DLOG("%04hX: Found IPv4 address: %s (key: %s)",
                         tx_id, ip_str, ares_dns_rr_key_tostr(keys[k]));

                    if (should_filter_dns_ip(ip_str, &cfg)) {
                        DLOG("%04hX: Found invalid IPv4 address: %s", tx_id, ip_str);
                        has_invalid = 1;
                        goto cleanup;  // 找到无效IP，直接退出
                    }
                }
            }
            else if (datatype == ARES_DATATYPE_INADDR6) {
                aaaa_record_count++;
                const struct ares_in6_addr *addr6 = ares_dns_rr_get_addr6(rr, keys[k]);
                if (addr6) {
                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, addr6, ip_str, sizeof(ip_str));
                    DLOG("%04hX: Found IPv6 address: %s (key: %s)",
                         tx_id, ip_str, ares_dns_rr_key_tostr(keys[k]));

                    if (should_filter_dns_ip(ip_str, &cfg)) {
                        DLOG("%04hX: Found invalid IPv6 address: %s", tx_id, ip_str);
                        has_invalid = 1;
                        goto cleanup;
                    }
                }
            }
        }
    }

cleanup:
    DLOG("%04hX: Summary - A records: %d, AAAA records: %d, has_invalid: %d",
         tx_id, a_record_count, aaaa_record_count, has_invalid);

    ares_dns_record_destroy(dnsrec);
    return has_invalid;
}

static void https_fetch_ctx_cleanup(https_client_t *client,
                                    struct https_fetch_ctx *prev,
                                    struct https_fetch_ctx *ctx,
                                    int curl_result_code);

static size_t write_buffer(void *buf, size_t size, size_t nmemb, void *userp) {
  GET_PTR(struct https_fetch_ctx, ctx, userp);
  size_t write_size = size * nmemb;
  size_t new_size = ctx->buflen + write_size;
  if (new_size > DOH_MAX_RESPONSE_SIZE) {
    WLOG_REQ("Response size is too large!");
    return 0;
  }
  char *new_buf = (char *)realloc(ctx->buf, new_size + 1);
  if (new_buf == NULL) {
    ELOG_REQ("Out of memory!");
    return 0;
  }
  ctx->buf = new_buf;
  memcpy(&(ctx->buf[ctx->buflen]), buf, write_size);
  ctx->buflen = new_size;
  // We always expect to receive valid non-null ASCII but just to be safe...
  ctx->buf[ctx->buflen] = '\0';
  return write_size;
}

void https_client_set_fallback(const char *dns_servers) {
    fallback_dns_servers = dns_servers;
    use_fallback = (dns_servers != NULL && *dns_servers != '\0');
    if (use_fallback) {
        ILOG("Fallback DNS enabled: %s", dns_servers);
    }
}

static int query_fallback_dns(uint16_t id, const uint8_t *query, size_t query_len,
        uint8_t *response, size_t *response_len) {
    if (!use_fallback) {
        return -1;
    }

    char servers[256];
    strncpy(servers, fallback_dns_servers, sizeof(servers) - 1);
    servers[sizeof(servers) - 1] = '\0';

    char *saveptr = NULL;
    char *server = strtok_r(servers, ",", &saveptr);
    while (server) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53);

        if (inet_pton(AF_INET, server, &addr.sin_addr) == 1) {
            DLOG("%04hX: Trying fallback DNS %s", id, server);

            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) {
                server = strtok_r(NULL, ",", &saveptr);
                continue;
            }

            struct timeval tv = {1, 0};
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            ssize_t sent = sendto(sock, query, query_len, 0,
                    (struct sockaddr*)&addr, sizeof(addr));
            if (sent == (ssize_t)query_len) {
                ssize_t recv_len = recvfrom(sock, response, 512, 0, NULL, NULL);
                close(sock);

                if (recv_len > 0) {
                    *response_len = (size_t)recv_len;
                    DLOG("%04hX: Fallback DNS success from %s", id, server);
                    return 0;
                }
            } else {
                close(sock);
            }
        }
        server = strtok_r(NULL, ",", &saveptr);
    }

    return -1;
}

static curl_socket_t opensocket_callback(void *clientp, curlsocktype purpose,
                                         struct curl_sockaddr *addr) {
  GET_PTR(https_client_t, client, clientp);

  if (client->connections >= HTTPS_SOCKET_LIMIT) {
    ELOG("curl needed more socket, than the number of maximum sockets: %d", HTTPS_SOCKET_LIMIT);
    return CURL_SOCKET_BAD;
  }

  curl_socket_t sock = socket(addr->family, addr->socktype, addr->protocol);
  if (sock == -1) {
    ELOG("Could not open curl socket %d:%s", errno, strerror(errno));
    return CURL_SOCKET_BAD;
  }

  DLOG("curl opened socket: %d", sock);
  client->connections++;

  if (client->stat) {
    stat_connection_opened(client->stat);
  }

#if defined(IP_TOS)
  if (purpose != CURLSOCKTYPE_IPCXN) {
    return sock;
  }

  if (addr->family == AF_INET) {
    setsockopt(sock, IPPROTO_IP, IP_TOS,
               &client->opt->dscp, sizeof(client->opt->dscp));
  }
#if defined(IPV6_TCLASS)
  else if (addr->family == AF_INET6) {
    setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS,
               &client->opt->dscp, sizeof(client->opt->dscp));
  }
#endif
#endif

  return sock;
}

static int closesocket_callback(void __attribute__((unused)) *clientp, curl_socket_t sock)
{
  GET_PTR(https_client_t, client, clientp);

  if (close(sock) != 0) {
    ELOG("Could not close curl socket %d:%s", errno, strerror(errno));
    return 1;
  }

  DLOG("curl closed socket: %d", sock);
  client->connections--;

  if (client->connections <= 0 && ev_is_active(&client->reset_timer)) {
    ILOG("Client reset timer cancelled, since all connection closed");
    ev_timer_stop(client->loop, &client->reset_timer);
  }

  if (client->stat) {
    stat_connection_closed(client->stat);
  }

  return 0;
}

static void https_log_data(int level, struct https_fetch_ctx *ctx,
                           const char * prefix, char *ptr, size_t size)
{
  const size_t width = 0x10;

  for (size_t i = 0; i < size; i += width) {
    char hex[3 * width + 1];
    char str[width + 1];
    size_t hex_off = 0;
    size_t str_off = 0;
    memset(hex, 0, sizeof(hex));
    memset(str, 0, sizeof(str));

    for (size_t c = 0; c < width; c++) {
      if (i+c < size) {
        hex_off += (size_t)snprintf(hex + hex_off, sizeof(hex) - hex_off,
                                    "%02x ", (unsigned char)ptr[i+c]);
        str_off += (size_t)snprintf(str + str_off, sizeof(str) - str_off,
                                    "%c", isprint(ptr[i+c]) ? ptr[i+c] : '.');
      } else {
        hex_off += (size_t)snprintf(hex + hex_off, sizeof(hex) - hex_off, "   ");
      }
    }

    LOG_REQ(level, "%s%4.4lx: %s%s", prefix, (long)i, hex, str);
  }
}

static
int https_curl_debug(CURL __attribute__((unused)) * handle, curl_infotype type,
                     char *data, size_t size, void *userp)
{
  GET_PTR(struct https_fetch_ctx, ctx, userp);
  const char *prefix = NULL;

  switch (type) {
    case CURLINFO_TEXT:
      prefix = "* ";
      break;
    case CURLINFO_HEADER_OUT:
      prefix = "> ";
      break;
    case CURLINFO_HEADER_IN:
      prefix = "< ";
      break;
    // not dumping DNS packets because of privacy
    case CURLINFO_DATA_OUT:
    case CURLINFO_DATA_IN:
      https_log_data(DOH_LOG_DEBUG, ctx, (type == CURLINFO_DATA_IN ? "< " : "> "), data, size);
      return 0;
    // uninformative
    case CURLINFO_SSL_DATA_OUT:
    case CURLINFO_SSL_DATA_IN:
      return 0;
    default:
      WLOG("Unhandled curl info type: %d", type);
      return 0;
  }

  // for extra debugging purpose
  // if (type != CURLINFO_TEXT) {
  //   https_log_data(DOH_LOG_DEBUG, ctx, "", data, size);
  // }

  // process lines one-by one
  char *start = NULL; // start position of currently processed line
  for (char *pos = data; pos <= (data + size); pos++) {
    // tokenize by end of string and line splitting characters
    if (pos == (data + size) || *pos == '\r' || *pos == '\n') {
      // skip empty string and curl info Expire
      if (start != NULL && (pos - start) > 0 &&
          strncmp(start, "Expire", sizeof("Expire") - 1) != 0) {
        // https_log_data(DOH_LOG_DEBUG, ctx, "", start, pos - start);
        DLOG_REQ("%s%.*s", prefix, pos - start, start);
        start = NULL;
      }
    } else if (start == NULL) {
      start = pos;
    }
  }
  return 0;
}

static const char * http_version_str(const long version) {
  switch (version) {
    case CURL_HTTP_VERSION_1_0:
      return "1.0";
    case CURL_HTTP_VERSION_1_1:
      return "1.1";
    case CURL_HTTP_VERSION_2_0: // fallthrough
    case CURL_HTTP_VERSION_2TLS:
      return "2";
    case CURL_HTTP_VERSION_3:
      return "3";
    default:
      FLOG("Unsupported HTTP version: %d", version);
  }
  return "UNKNOWN"; // unreachable code
}

static void https_set_request_version(https_client_t *client,
                                      struct https_fetch_ctx *ctx) {
  long http_version_int = CURL_HTTP_VERSION_2TLS;
  switch (client->opt->use_http_version) {
    case 1:
      http_version_int = CURL_HTTP_VERSION_1_1;
      __attribute__((fallthrough));
    case 2:
      break;
    case 3:
      http_version_int = CURL_HTTP_VERSION_3;
      break;
    default:
      FLOG_REQ("Invalid HTTP version: %d", client->opt->use_http_version);
  }
  DLOG_REQ("Requesting HTTP/%s", http_version_str(http_version_int));

  CURLcode easy_code = curl_easy_setopt(ctx->curl, CURLOPT_HTTP_VERSION, http_version_int);
  if (easy_code != CURLE_OK) {
    ELOG_REQ("Setting HTTP/%s version failed with %d: %s",
             http_version_str(http_version_int), easy_code, curl_easy_strerror(easy_code));

    if (client->opt->use_http_version == 3) {
      ELOG("Try to run application without -q argument!");
    } else if (client->opt->use_http_version == 2) {
      ELOG("Try to run application with -x argument! Falling back to HTTP/1.1 version.");
    }
  }
}

static void https_fetch_ctx_init(https_client_t *client,
                                 struct https_fetch_ctx *ctx, const char *url,
                                 const char* data, size_t datalen,
                                 struct curl_slist *resolv, uint16_t id,
                                 https_response_cb cb, void *cb_data) {
  ctx->curl = curl_easy_init(); // if fails, first setopt will fail
  ctx->id = id;
  ctx->cb = cb;
  ctx->cb_data = cb_data;
  ctx->buf = NULL;
  ctx->buflen = 0;
  ctx->next = client->fetches;
  client->fetches = ctx;

  // 新增：保存查询数据的副本 ★★★
  ctx->query_data = malloc(datalen);
  if (ctx->query_data) {
      memcpy(ctx->query_data, data, datalen);
      ctx->query_len = datalen;
  } else {
      FLOG_REQ("Failed to allocate query data buffer");
  }

  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_RESOLVE, resolv);

  https_set_request_version(client, ctx);

  if (logging_debug_enabled()) {
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_VERBOSE, 1L);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_DEBUGFUNCTION, https_curl_debug);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_DEBUGDATA, ctx);
  }
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_OPENSOCKETDATA, client);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_CLOSESOCKETFUNCTION, closesocket_callback);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_CLOSESOCKETDATA, client);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_URL, url);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_HTTPHEADER, client->header_list);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_POSTFIELDSIZE, datalen);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_POSTFIELDS, data);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_WRITEFUNCTION, &write_buffer);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_WRITEDATA, ctx);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_MAXAGE_CONN, (long)client->opt->max_idle_time);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_PIPEWAIT, (long)(client->opt->use_http_version > 1));
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_USERAGENT, "https_dns_proxy/0.4");
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_FOLLOWLOCATION, 0L);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_NOSIGNAL, 1L);  // Disable curl's signal handling to avoid conflicts with libev
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_TIMEOUT, client->connections > 0 ? 5L : 10L /* seconds */);
  // We know Google supports this, so force it.
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_ERRORBUFFER, ctx->curl_errbuf); // zeroed by calloc
  if (client->opt->curl_proxy) {
    DLOG_REQ("Using curl proxy: %s", client->opt->curl_proxy);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_PROXY, client->opt->curl_proxy);
  }
  if (client->opt->source_addr) {
    DLOG_REQ("Using source address: %s", client->opt->source_addr);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_INTERFACE, client->opt->source_addr);
  }
  if (client->opt->ca_info) {
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_CAINFO, client->opt->ca_info);
  }
  CURLMcode multi_code = curl_multi_add_handle(client->curlm, ctx->curl);
  if (multi_code != CURLM_OK) {
    ELOG_REQ("curl_multi_add_handle error %d: %s", multi_code, curl_multi_strerror(multi_code));
    if (multi_code == CURLE_ABORTED_BY_CALLBACK) {
      WLOG_REQ("Resetting HTTPS client to recover from faulty state!");
      https_client_reset(client);
    } else {
      https_fetch_ctx_cleanup(client, NULL, client->fetches, -1);  // dropping current failed request
    }
  }
}

static int https_fetch_ctx_process_response(https_client_t *client,
                                            struct https_fetch_ctx *ctx,
                                            CURLcode curl_result_code)
{
  CURLcode res = 0;
  long long_resp = 0;
  char *str_resp = NULL;
  int faulty_response = 1;

  switch (curl_result_code) {
    case CURLE_OK:
      DLOG_REQ("curl request succeeded");
      faulty_response = 0;
      break;
    case CURLE_WRITE_ERROR:
      WLOG_REQ("curl request failed with write error (probably response content was too large)");
      break;
    case CURLE_OPERATION_TIMEDOUT:
      if (!ev_is_active(&client->reset_timer)) {
        ILOG_REQ("Client reset timer started");
        ev_timer_start(client->loop, &client->reset_timer);
      }
      __attribute__((fallthrough));
    default:
      WLOG_REQ("curl request failed with %d: %s", curl_result_code, curl_easy_strerror(curl_result_code));
      if (ctx->curl_errbuf[0] != 0) {
        WLOG_REQ("curl error message: %s", ctx->curl_errbuf);
      }
  }

  res = curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &long_resp);
  if (res != CURLE_OK) {
    ELOG_REQ("CURLINFO_RESPONSE_CODE: %s", curl_easy_strerror(res));
    faulty_response = 1;
  } else if (long_resp != 200) {
    faulty_response = 1;
    if (long_resp == 0) {
      curl_off_t uploaded_bytes = 0;
      if (curl_easy_getinfo(ctx->curl, CURLINFO_SIZE_UPLOAD_T, &uploaded_bytes) == CURLE_OK &&
          uploaded_bytes > 0) {
        WLOG_REQ("Connecting and sending request to resolver was successful, "
                 "but no response was sent back");
        if (client->opt->use_http_version == 1) {
          // for example Unbound DoH servers does not support HTTP/1.x, only HTTP/2
          WLOG("Resolver may not support current HTTP/%s protocol version",
               http_version_str(client->opt->use_http_version));
        }
      } else {
        // in case of HTTP/1.1 this can happen very often depending on DNS query frequency
        // example: server side closes the connection or curl force closes connections
        // that have been opened a long time ago (if CURLOPT_MAXAGE_CONN can not be increased
        // it is 118 seconds)
        // also: when no internet connection, this floods the log for every failed request
        WLOG_REQ("No response (probably connection has been closed or timed out)");
      }
    } else {
      WLOG_REQ("curl response code: %d, content length: %zu", long_resp, ctx->buflen);
      if (ctx->buflen > 0) {
        https_log_data(DOH_LOG_WARNING, ctx, "", ctx->buf, ctx->buflen);
      }
    }
  }

  if (!faulty_response)
  {
    res = curl_easy_getinfo(ctx->curl, CURLINFO_CONTENT_TYPE, &str_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_CONTENT_TYPE: %s", curl_easy_strerror(res));
    } else if (str_resp == NULL ||
        strncmp(str_resp, DOH_CONTENT_TYPE, sizeof(DOH_CONTENT_TYPE) - 1) != 0) {  // at least, start with it
      WLOG_REQ("Invalid response Content-Type: %s", str_resp ? str_resp : "UNSET");
      faulty_response = 1;
    }

    // 检查DNS响应内容
    if (ctx->buf && ctx->buflen > 0) {
      ares_dns_record_t *dnsrec = NULL;
      ares_status_t status = ares_dns_parse((const uint8_t*)ctx->buf, ctx->buflen, 0, &dnsrec);

      if (status == ARES_SUCCESS) {
        uint16_t rcode = ares_dns_record_get_rcode(dnsrec);
        size_t answer_count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
        const uint16_t tx_id = ares_dns_record_get_id(dnsrec);

        DLOG_REQ("DNS response - rcode: %d, answer_count: %zu", rcode, answer_count);

        // 判断是否需要回退的条件：
        // 1. 如果有ANSWER记录，检查IP有效性
        // 2. 如果没有ANSWER记录（包括NXDOMAIN），根据配置决定是否回退
        // 这里我们实现：任何非成功rcode或没有ANSWER记录都触发回退

        if (rcode != ARES_RCODE_NOERROR) {
          DLOG_REQ("RCODE=%d not NOERROR, triggering fallback", rcode);
          faulty_response = 1;
        }
        else if (answer_count == 0) {
          DLOG_REQ("No answer records (rcode=%d), triggering fallback", rcode);
          faulty_response = 1;
        }
        else {
          // 有ANSWER记录，检查IP有效性
          if (dns_response_has_invalid_ips((uint8_t*)ctx->buf, ctx->buflen)) {
              ELOG_REQ("Response contains invalid IP addresses, treating as faulty");
              faulty_response = 1;
          }
        }

        ares_dns_record_destroy(dnsrec);
      } else {
        DLOG_REQ("Failed to parse DNS response, triggering fallback");
        faulty_response = 1;
      }
    }
  }

  if (logging_debug_enabled() || faulty_response || ctx->buflen == 0) {
    res = curl_easy_getinfo(ctx->curl, CURLINFO_REDIRECT_URL, &str_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_REDIRECT_URL: %s", curl_easy_strerror(res));
    } else if (str_resp != NULL) {
      WLOG_REQ("Request would be redirected to: %s", str_resp);
      if (strcmp(str_resp, client->opt->resolver_url) != 0) {
        WLOG("Please update Resolver URL to avoid redirection!");
      }
    }

    res = curl_easy_getinfo(ctx->curl, CURLINFO_SSL_VERIFYRESULT, &long_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_SSL_VERIFYRESULT: %s", curl_easy_strerror(res));
    } else if (long_resp != 0) {
      WLOG_REQ("CURLINFO_SSL_VERIFYRESULT: certificate verification failure %d", long_resp);
    }

    res = curl_easy_getinfo(ctx->curl, CURLINFO_OS_ERRNO, &long_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_OS_ERRNO: %s", curl_easy_strerror(res));
    } else if (long_resp != 0) {
      WLOG_REQ("CURLINFO_OS_ERRNO: %d %s", long_resp, strerror((int)long_resp));
      if (long_resp == ENETUNREACH && !client->opt->ipv4) {
        // this can't be fixed here with option overwrite because of dns_poller
        WLOG("Try to run application with -4 argument!");
      }
    }
  }

  if (logging_debug_enabled() || client->stat) {
    res = curl_easy_getinfo(ctx->curl, CURLINFO_NUM_CONNECTS , &long_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_NUM_CONNECTS: %s", curl_easy_strerror(res));
    } else {
      DLOG_REQ("CURLINFO_NUM_CONNECTS: %d", long_resp);
      if (long_resp == 0 && client->stat) {
        stat_connection_reused(client->stat);
      }
    }
  }

  if (logging_debug_enabled()) {
    res = curl_easy_getinfo(ctx->curl, CURLINFO_EFFECTIVE_URL, &str_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_EFFECTIVE_URL: %s", curl_easy_strerror(res));
    } else {
      DLOG_REQ("CURLINFO_EFFECTIVE_URL: %s", str_resp);
    }

    res = curl_easy_getinfo(ctx->curl, CURLINFO_HTTP_VERSION, &long_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_HTTP_VERSION: %s", curl_easy_strerror(res));
    } else if (long_resp != CURL_HTTP_VERSION_NONE) {
      DLOG_REQ("CURLINFO_HTTP_VERSION: %s", http_version_str(long_resp));
    }

    res = curl_easy_getinfo(ctx->curl, CURLINFO_SCHEME, &str_resp);
    if (res != CURLE_OK) {
      ELOG_REQ("CURLINFO_SCHEME: %s", curl_easy_strerror(res));
    } else if (str_resp != NULL && strcasecmp(str_resp, "https") != 0) {
      DLOG_REQ("CURLINFO_SCHEME: %s", str_resp);
    }

    double namelookup_time = NAN;
    double connect_time = NAN;
    double appconnect_time = NAN;
    double pretransfer_time = NAN;
    double starttransfer_time = NAN;
    double total_time = NAN;
    if (curl_easy_getinfo(ctx->curl,
                          CURLINFO_NAMELOOKUP_TIME, &namelookup_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_CONNECT_TIME, &connect_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_APPCONNECT_TIME, &appconnect_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_PRETRANSFER_TIME, &pretransfer_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_STARTTRANSFER_TIME, &starttransfer_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_TOTAL_TIME, &total_time) != CURLE_OK) {
      ELOG_REQ("Error getting timing");
    } else {
      DLOG_REQ("Times: %lf, %lf, %lf, %lf, %lf, %lf",
               namelookup_time, connect_time, appconnect_time, pretransfer_time,
               starttransfer_time, total_time);
    }
  }

  return faulty_response;
}

static void https_fetch_ctx_cleanup(https_client_t *client,
                                    struct https_fetch_ctx *prev,
                                    struct https_fetch_ctx *ctx,
                                    int curl_result_code) {
  CURLMcode code = curl_multi_remove_handle(client->curlm, ctx->curl);
  if (code != CURLM_OK) {
    FLOG_REQ("curl_multi_remove_handle error %d: %s", code, curl_multi_strerror(code));
  }
  int drop_reply = 0;

  if (curl_result_code < 0) {
    WLOG_REQ("Request was aborted");
    drop_reply = 1;
  } else if (https_fetch_ctx_process_response(client, ctx, (CURLcode)curl_result_code) != 0) {
    ILOG_REQ("Response was faulty or not invalid ip, skipping DNS reply");
    drop_reply = 1;
  }

  // ===== 从这里开始添加后备逻辑 =====
  // Try fallback DNS if DoH failed
  if (drop_reply && use_fallback && client->opt && client->opt->resolver_url) {
      DLOG_REQ("DoH failed, trying fallback DNS");

      uint8_t fallback_response[512];
      size_t fallback_len = 0;

      // 使用保存的查询数据
      if (ctx->query_data && ctx->query_len > 0) {
          DLOG_REQ("Using saved query data, len=%zu", ctx->query_len);

          if (query_fallback_dns(ctx->id,
                      ctx->query_data,
                      ctx->query_len,
                      fallback_response, &fallback_len) == 0) {

              DLOG_REQ("Fallback DNS succeeded, using result");

              // 释放原来的 buf（如果有）
              if (ctx->buf) {
                  free(ctx->buf);
                  ctx->buf = NULL;
              }

              ctx->buf = malloc(fallback_len);
              if (ctx->buf) {
                  memcpy(ctx->buf, fallback_response, fallback_len);
                  ctx->buflen = fallback_len;
                  drop_reply = 0;  // 取消丢弃标记

                  DLOG_REQ("Fallback DNS result prepared, len=%zu", fallback_len);
              }
          } else {
              DLOG_REQ("Fallback DNS also failed");
          }
      } else {
          DLOG_REQ("No saved query data available");
      }
  }
  // ===== 结束添加 =====

  if (drop_reply) {
    free(ctx->buf);
    ctx->buf = NULL;
    ctx->buflen = 0;
  }
  // callback must be called to avoid memleak
  ctx->cb(ctx->cb_data, ctx->buf, ctx->buflen);
  curl_easy_cleanup(ctx->curl);
  free(ctx->buf);
  if (ctx->query_data) {
      free(ctx->query_data);
      ctx->query_data = NULL;
  }

  if (prev) {
    prev->next = ctx->next;
  } else {
    client->fetches = ctx->next;
  }
  free(ctx);
}

static void check_multi_info(https_client_t *c) {
  CURLMsg *msg = NULL;
  int msgs_left = 0;
  while ((msg = curl_multi_info_read(c->curlm, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      struct https_fetch_ctx *prev = NULL;
      struct https_fetch_ctx *cur = c->fetches;
      while (cur) {
        if (cur->curl == msg->easy_handle) {
          https_fetch_ctx_cleanup(c, prev, cur, (int)msg->data.result);
          break;
        }
        prev = cur;
        cur = cur->next;
      }
    }
    else {
      ELOG("Unhandled curl message: %d", msg->msg);  // unlikely
    }
  }
}

static void sock_cb(struct ev_loop __attribute__((unused)) *loop,
                    struct ev_io *w, int revents) {
  GET_PTR(https_client_t, c, w->data);
  int ignore = 0;
  CURLMcode code = curl_multi_socket_action(
      c->curlm, w->fd, (revents & EV_READ ? CURL_CSELECT_IN : 0) |
                       (revents & EV_WRITE ? CURL_CSELECT_OUT : 0),
      &ignore);
  if (code == CURLM_OK) {
    check_multi_info(c);
  }
  else {
    FLOG("curl_multi_socket_action error %d: %s", code, curl_multi_strerror(code));
    if (code == CURLE_ABORTED_BY_CALLBACK) {
      WLOG("Resetting HTTPS client to recover from faulty state!");
      https_client_reset(c);
    }
  }
}

static void timer_cb(struct ev_loop __attribute__((unused)) *loop,
                     struct ev_timer *w, int __attribute__((unused)) revents) {
  GET_PTR(https_client_t, c, w->data);
  int ignore = 0;
  CURLMcode code = curl_multi_socket_action(c->curlm, CURL_SOCKET_TIMEOUT, 0,
                                            &ignore);
  if (code != CURLM_OK) {
    ELOG("curl_multi_socket_action error %d: %s", code, curl_multi_strerror(code));
  }
  check_multi_info(c);
}

static struct ev_io * get_io_event(struct ev_io io_events[], curl_socket_t sock) {
  for (int i = 0; i < HTTPS_SOCKET_LIMIT; i++) {
    if (io_events[i].fd == sock) {
      return &io_events[i];
    }
  }
  return NULL;
}

static void dump_io_events(struct ev_io io_events[]) {
  for (int i = 0; i < HTTPS_SOCKET_LIMIT; i++) {
    ILOG("IO event #%d: fd=%d, events=%d/%s%s",
         i+1, io_events[i].fd, io_events[i].events,
         (io_events[i].events & EV_READ ? "R" : ""),
         (io_events[i].events & EV_WRITE ? "W" : ""));
  }
}

static int multi_sock_cb(CURL *curl, curl_socket_t sock, int what,
                         void *userp, void __attribute__((unused)) *sockp) {
  GET_PTR(https_client_t, c, userp);
  if (!curl) {
    FLOG("Unexpected NULL pointer for CURL");
  }
  // stop and release used event
  struct ev_io *io_event_ptr = get_io_event(c->io_events, sock);
  if (io_event_ptr) {
    ev_io_stop(c->loop, io_event_ptr);
    io_event_ptr->fd = 0;
    DLOG("Released used io event: %p", io_event_ptr);
  }
  if (what == CURL_POLL_REMOVE) {
    return 0;
  }
  // reserve and start new event on unused slot
  io_event_ptr = get_io_event(c->io_events, 0);
  if (!io_event_ptr) {
    ELOG("curl needed more IO event handler, than the number of maximum sockets: %d", HTTPS_SOCKET_LIMIT);
    dump_io_events(c->io_events);
    logging_flight_recorder_dump();
    return -1;
  }
  DLOG("Reserved new io event: %p", io_event_ptr);
  ev_io_init(io_event_ptr, sock_cb, sock,
             ((what & CURL_POLL_IN) ? EV_READ : 0) |
             ((what & CURL_POLL_OUT) ? EV_WRITE : 0));
  ev_io_start(c->loop, io_event_ptr);
  return 0;
}

static int multi_timer_cb(CURLM __attribute__((unused)) *multi,
                          long timeout_ms, void *userp) {
  GET_PTR(https_client_t, c, userp);
  ev_timer_stop(c->loop, &c->timer);
  if (timeout_ms >= 0) {
    ev_timer_init(&c->timer, timer_cb, (double)timeout_ms / 1000.0, 0);
    ev_timer_start(c->loop, &c->timer);
  }
  return 0;
}

static void https_client_multi_init(https_client_t *c, struct curl_slist *header_list) {
  c->curlm = curl_multi_init(); // if fails, first setopt will fail
  c->header_list = header_list;

  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_MAX_TOTAL_CONNECTIONS, HTTPS_CONNECTION_LIMIT);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_MAX_HOST_CONNECTIONS, HTTPS_CONNECTION_LIMIT);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_SOCKETDATA, c);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_SOCKETFUNCTION, multi_sock_cb);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_TIMERDATA, c);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
}

static void reset_timer_cb(struct ev_loop __attribute__((unused)) *loop,
    ev_timer *w, int __attribute__((unused)) revents) {
  GET_PTR(https_client_t, c, w->data);
  ILOG("Client reset timer timeouted");
  https_client_reset(c);
}

void https_client_init(https_client_t *c, options_t *opt,
                       stat_t *stat, struct ev_loop *loop) {
  memset(c, 0, sizeof(*c));
  c->loop = loop;
  c->fetches = NULL;
  c->timer.data = c;
  for (int i = 0; i < HTTPS_SOCKET_LIMIT; i++) {
    c->io_events[i].data = c;
  }
  c->opt = opt;
  c->stat = stat;

  ev_timer_init(&c->reset_timer, reset_timer_cb, (double)opt->conn_loss_time, 0);
  c->reset_timer.data = c;

  struct curl_slist *header_list = curl_slist_append(curl_slist_append(NULL,
    "Accept: " DOH_CONTENT_TYPE),
    "Content-Type: " DOH_CONTENT_TYPE);
  https_client_multi_init(c, header_list);
}

void https_client_fetch(https_client_t *c, const char *url,
                        const char* postdata, size_t postdata_len,
                        struct curl_slist *resolv, uint16_t id,
                        https_response_cb cb, void *data) {
  struct https_fetch_ctx *ctx =
      (struct https_fetch_ctx *)calloc(1, sizeof(struct https_fetch_ctx));
  if (!ctx) {
    FLOG("Out of mem");
  }
  https_fetch_ctx_init(c, ctx, url, postdata, postdata_len, resolv, id, cb, data);
}

void https_client_reset(https_client_t *c) {
  struct curl_slist *header_list = c->header_list;
  c->header_list = NULL;
  https_client_cleanup(c);
  https_client_multi_init(c, header_list);
}

void https_client_cleanup(https_client_t *c) {
  while (c->fetches) {
    https_fetch_ctx_cleanup(c, NULL, c->fetches, -1);
  }
  curl_slist_free_all(c->header_list);
  curl_multi_cleanup(c->curlm);
  ev_timer_stop(c->loop, &c->reset_timer);
}

// 在 https_client.c 中添加
int https_client_fallback_enabled(void) {
    return use_fallback && fallback_dns_servers != NULL;
}

int https_client_fallback_query(uint16_t id, const uint8_t *query, size_t query_len,
                                uint8_t *response, size_t *response_len) {
    if (!use_fallback || !fallback_dns_servers) {
        return -1;
    }
    return query_fallback_dns(id, query, query_len, response, response_len);
}


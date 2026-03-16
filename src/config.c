#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "logging.h"
#include "options.h"

#define MAX_LINE_LENGTH 1024

// 去除字符串首尾空白
static char *trim_whitespace(char *str) {
    char *end = NULL;

    // 跳过前导空白
    while(isspace((unsigned char)*str)) { { str++;
    }
    }

    if(*str == 0) { { return str;
    }
    }

    // 移除尾部空白
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) { { end--;
    }
    }

    end[1] = '\0';
    return str;
}

// 解析键值对
static int parse_key_value(char *line, char **key, char **value) {
    char *equals = strchr(line, '=');
    if (!equals) {
        return 0;
    }

    *equals = '\0';
    *key = trim_whitespace(line);

    // 处理等号后面的内容，可能为空
    char *val_start = equals + 1;
    while (isspace((unsigned char)*val_start)) { { val_start++;
}
}
    *value = val_start;  // 即使为空字符串也允许

    // 键不能为空
    if (*key[0] == '\0') { { return 0;
}
}
    return 1;  // 值可以为空
}

// 字符串转整数
static int parse_int_value(const char *value, int *result) {
    char *endptr = NULL;
    long val = strtol(value, &endptr, 10);

    if (*endptr != '\0' || val < INT32_MIN || val > INT32_MAX) {
        return 0;
    }

    *result = (int)val;
    return 1;
}

// 解析布尔值
static int parse_bool_value(const char *value) {
    if (strcasecmp(value, "yes") == 0 ||
            strcasecmp(value, "true") == 0 ||
            strcmp(value, "1") == 0) {
        return 1;
    }
    return 0;
}

enum ConfigParseResult config_load(const char *config_file, struct Options *opt) {
    FILE *fp = fopen(config_file, "re");
    if (!fp) {
        if (errno == ENOENT) {
            return CPR_FILE_NOT_FOUND;
        }
        return CPR_PARSE_ERROR;
    }

    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    int parse_error = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        // 移除末尾换行符
        char *p = strchr(line, '\n');
        if (p) { { *p = '\0';
        }
        }

        // 跳过空行和注释
        char *trimmed = trim_whitespace(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            continue;
        }

        char *key = NULL;
        char *value = NULL;

        if (!parse_key_value(trimmed, &key, &value)) {
            fprintf(stderr, "Config file line %d: Invalid format (expected 'key = value')\n", line_num);
            parse_error = 1;
            continue;
        }

        // 映射配置项到命令行参数
        if (strcmp(key, "listen_addr") == 0) {
            if (value[0] != '\0') {
                opt->listen_addr = strdup(value);
            }
        }
        else if (strcmp(key, "listen_port") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->listen_port)) {
                    fprintf(stderr, "Config line %d: Invalid port number '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "tcp_client_limit") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->tcp_client_limit)) {
                    fprintf(stderr, "Config line %d: Invalid TCP client limit '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "daemonize") == 0) {
            if (value[0] != '\0') {
                opt->daemonize = parse_bool_value(value);
            }
        }
        else if (strcmp(key, "user") == 0) {
            if (value[0] != '\0') {
                opt->user = strdup(value);
            }
        }
        else if (strcmp(key, "group") == 0) {
            if (value[0] != '\0') {
                opt->group = strdup(value);
            }
        }
        else if (strcmp(key, "bootstrap_dns") == 0) {
            if (value[0] != '\0') {
                opt->bootstrap_dns = strdup(value);
            }
        }
        else if (strcmp(key, "polling_interval") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->bootstrap_dns_polling_interval)) {
                    fprintf(stderr, "Config line %d: Invalid polling interval '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "ipv4_only") == 0) {
            if (value[0] != '\0') {
                opt->ipv4 = parse_bool_value(value);
            }
        }
        else if (strcmp(key, "dscp") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->dscp)) {
                    fprintf(stderr, "Config line %d: Invalid DSCP value '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "resolver_url") == 0) {
            if (value[0] != '\0') {
                opt->resolver_url = strdup(value);
            }
        }
        else if (strcmp(key, "proxy") == 0) {
            // 允许为空字符串，表示不使用代理
            if (value[0] != '\0') {
                opt->curl_proxy = strdup(value);
            } else {
                opt->curl_proxy = NULL;  // 显式设置为 NULL
            }
        }
        else if (strcmp(key, "source_addr") == 0) {
            // 允许为空字符串，表示使用系统默认
            if (value[0] != '\0') {
                opt->source_addr = strdup(value);
            } else {
                opt->source_addr = NULL;  // 显式设置为 NULL
            }
        }
        else if (strcmp(key, "http_version") == 0) {
            if (value[0] != '\0') {
                if (strcmp(value, "1.1") == 0) {
                    opt->use_http_version = 1;
                } else if (strcmp(value, "2") == 0) {
                    opt->use_http_version = 2;
                } else if (strcmp(value, "3") == 0) {
                    opt->use_http_version = 3;
                } else {
                    fprintf(stderr, "Config line %d: Invalid HTTP version '%s' (use 1.1, 2, or 3)\n",
                            line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "max_idle_time") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->max_idle_time)) {
                    fprintf(stderr, "Config line %d: Invalid max idle time '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "conn_loss_time") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->conn_loss_time)) {
                    fprintf(stderr, "Config line %d: Invalid connection loss time '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "ca_info") == 0) {
            if (value[0] != '\0') {
                opt->ca_info = strdup(value);
            } else {
                opt->ca_info = NULL;
            }
        }
        else if (strcmp(key, "logfile") == 0) {
            if (value[0] != '\0') {
                opt->logfile = strdup(value);
            }
        }
        else if (strcmp(key, "loglevel") == 0) {
            if (value[0] != '\0') {
                if (strcasecmp(value, "debug") == 0) {
                    opt->loglevel = DOH_LOG_DEBUG;
                } else if (strcasecmp(value, "info") == 0) {
                    opt->loglevel = DOH_LOG_INFO;
                } else if (strcasecmp(value, "warning") == 0) {
                    opt->loglevel = DOH_LOG_WARNING;
                } else if (strcasecmp(value, "error") == 0) {
                    opt->loglevel = DOH_LOG_ERROR;
                } else if (strcasecmp(value, "fatal") == 0) {
                    opt->loglevel = DOH_LOG_FATAL;
                } else {
                    int level = 0;
                    if (parse_int_value(value, &level)) {
                        opt->loglevel = level;
                    } else {
                        fprintf(stderr, "Config line %d: Invalid log level '%s'\n", line_num, value);
                        parse_error = 1;
                    }
                }
            }
        }
        else if (strcmp(key, "use_syslog") == 0) {
            if (value[0] != '\0') {
                opt->use_syslog = parse_bool_value(value);
            }
        }
        else if (strcmp(key, "stats_interval") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->stats_interval)) {
                    fprintf(stderr, "Config line %d: Invalid stats interval '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "flight_recorder") == 0) {
            if (value[0] != '\0') {
                if (!parse_int_value(value, &opt->flight_recorder_size)) {
                    fprintf(stderr, "Config line %d: Invalid flight recorder size '%s'\n", line_num, value);
                    parse_error = 1;
                }
            }
        }
        else if (strcmp(key, "fallback_dns") == 0) {
            if (value[0] != '\0') {
                opt->fallback_dns = strdup(value);
            }
        }
        else {
            fprintf(stderr, "Config line %d: Unknown key '%s'\n", line_num, key);
            parse_error = 1;
        }
    }

    fclose(fp);

    return parse_error ? CPR_PARSE_ERROR : CPR_SUCCESS;
}

void config_show_help(void) {
    printf("\nConfiguration File Format:\n");
    printf("==========================\n");
    printf("# This is a comment\n");
    printf("key = value\n\n");

    printf("Available keys:\n");
    printf("  listen_addr           - Listen address (default: 127.0.0.1)\n");
    printf("  listen_port           - Listen port (default: 5053)\n");
    printf("  tcp_client_limit      - TCP client limit (default: 20)\n");
    printf("  daemonize             - Run as daemon (yes/no, default: no)\n");
    printf("  user                  - Run as user\n");
    printf("  group                 - Run as group\n");
    printf("  bootstrap_dns         - Bootstrap DNS servers (comma-separated)\n");
    printf("  polling_interval      - DNS polling interval (seconds)\n");
    printf("  ipv4_only             - Force IPv4 only (yes/no)\n");
    printf("  dscp                  - DSCP codepoint (0-63)\n");
    printf("  resolver_url          - DoH resolver URL\n");
    printf("  proxy                 - HTTP proxy\n");
    printf("  source_addr           - Source address\n");
    printf("  http_version          - HTTP version (1.1, 2, 3)\n");
    printf("  max_idle_time         - Max connection idle time (seconds)\n");
    printf("  conn_loss_time        - Connection loss tolerance (seconds)\n");
    printf("  ca_info               - CA certificates file\n");
    printf("  logfile               - Log file path\n");
    printf("  loglevel              - Log level (debug/info/warning/error/fatal)\n");
    printf("  use_syslog            - Use syslog (yes/no)\n");
    printf("  stats_interval        - Statistics interval (seconds)\n");
    printf("  flight_recorder       - Flight recorder size\n");
    printf("  fallback_dns          - Fallback DNS servers (comma-separated)\n");
    printf("\n");
    printf("Example configuration file:\n");
    printf("--------------------------\n");
    printf("# Basic settings\n");
    printf("listen_addr = 0.0.0.0\n");
    printf("listen_port = 5053\n");
    printf("tcp_client_limit = 50\n");
    printf("daemonize = yes\n");
    printf("user = nobody\n");
    printf("\n");
    printf("# DNS settings\n");
    printf("bootstrap_dns = 8.8.8.8,1.1.1.1\n");
    printf("polling_interval = 300\n");
    printf("ipv4_only = no\n");
    printf("fallback_dns = 8.8.8.8,4.4.4.4\n");
    printf("\n");
    printf("# DoH settings\n");
    printf("resolver_url = https://dns.google/dns-query\n");
    printf("http_version = 2\n");
    printf("max_idle_time = 300\n");
    printf("conn_loss_time = 30\n");
    printf("\n");
    printf("# Logging\n");
    printf("loglevel = info\n");
    printf("use_syslog = no\n");
    printf("logfile = /var/log/https_dns_proxy.log\n");
    printf("stats_interval = 60\n");
    printf("flight_recorder = 1000\n");
    printf("\n");
}

#!/usr/bin/env python
# coding=utf-8
"""
DoH (DNS over HTTPS) 测试服务器
用于测试 https_dns_proxy 的 IP 过滤和回退机制
"""

import argparse
import json
import socket
import struct
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import logging
from typing import Dict, Tuple, Optional, List, Any
import time
import base64

# DNS 头部常量
DNS_HEADER_LENGTH = 12
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_TYPE_CNAME = 5
DNS_CLASS_IN = 1

# DNS 响应码
DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5


class DNSMessage:
    """DNS 消息构建器"""

    @staticmethod
    def parse_question(data: bytes) -> Tuple[str, int, int]:
        """解析 DNS 问题部分"""
        offset = DNS_HEADER_LENGTH
        name_parts = []

        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:  # 压缩指针
                offset += 2
                break
            offset += 1
            name_parts.append(data[offset:offset+length].decode('ascii', errors='ignore'))
            offset += length

        if offset + 4 > len(data):
            raise ValueError("Incomplete DNS question")

        qtype = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        qclass = struct.unpack('!H', data[offset:offset+2])[0]

        return '.'.join(name_parts), qtype, qclass

    @staticmethod
    def build_response_header(query_id: int, flags: int, qdcount: int = 1,
                              ancount: int = 0, nscount: int = 0, arcount: int = 0) -> bytes:
        """构建 DNS 响应头部
        DNS头部格式:
        - ID (16 bits)
        - Flags (16 bits)
        - QDCOUNT (16 bits) - 问题数
        - ANCOUNT (16 bits) - 答案数
        - NSCOUNT (16 bits) - 权威记录数
        - ARCOUNT (16 bits) - 附加记录数
        """
        return struct.pack('!HHHHHH', query_id, flags, qdcount, ancount, nscount, arcount)

    @staticmethod
    def build_domain_name(name: str) -> bytes:
        """将域名转换为 DNS 格式"""
        parts = []
        for label in name.split('.'):
            if label:  # 跳过空标签
                parts.append(bytes([len(label)]))
                parts.append(label.encode('ascii'))
        parts.append(b'\x00')  # 结束符
        return b''.join(parts)

    @staticmethod
    def build_compressed_name() -> bytes:
        """构建压缩指针指向问题部分的域名"""
        return b'\xc0\x0c'  # 压缩指针，指向问题部分的域名

    @staticmethod
    def build_a_record(name: str, ip: str, ttl: int = 300) -> bytes:
        """构建 A 记录 (IPv4) - 完全信任配置文件"""
        # 使用压缩指针（指向问题部分的域名）
        name_bytes = DNSMessage.build_compressed_name()

        # 类型、类、TTL、数据长度
        record = name_bytes
        record += struct.pack('!HHIH', DNS_TYPE_A, DNS_CLASS_IN, ttl, 4)
        # IP地址 - 信任配置文件，不做验证
        try:
            ip_bytes = socket.inet_aton(ip)
        except (socket.error, OSError):
            # 如果真的格式错误，使用默认值
            logging.warning(f"Invalid IPv4 address format: '{ip}', using 123.123.123.123 instead")
            ip_bytes = socket.inet_aton('123.123.123.123')

        record += ip_bytes
        return record

    @staticmethod
    def build_aaaa_record(name: str, ip: str, ttl: int = 300) -> bytes:
        """构建 AAAA 记录 (IPv6) - 完全信任配置文件"""
        # 使用压缩指针（指向问题部分的域名）
        name_bytes = DNSMessage.build_compressed_name()

        # 类型、类、TTL、数据长度
        record = name_bytes
        record += struct.pack('!HHIH', DNS_TYPE_AAAA, DNS_CLASS_IN, ttl, 16)
        # IPv6地址 - 信任配置文件，不做验证
        try:
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
        except (socket.error, OSError):
            # 如果真的格式错误，使用默认值
            logging.warning(f"Invalid IPv6 address format: '{ip}', using 2001:db8::1234 instead")
            ip_bytes = socket.inet_pton(socket.AF_INET6, '2001:db8::1234')

        record += ip_bytes
        return record

    @staticmethod
    def build_cname_record(name: str, cname: str, ttl: int = 300) -> bytes:
        """构建 CNAME 记录"""
        # 使用压缩指针（指向问题部分的域名）
        name_bytes = DNSMessage.build_compressed_name()
        cname_bytes = DNSMessage.build_domain_name(cname)

        # 类型、类、TTL、数据长度
        record = name_bytes
        record += struct.pack('!HHIH', DNS_TYPE_CNAME, DNS_CLASS_IN, ttl, len(cname_bytes))
        record += cname_bytes
        return record

    @staticmethod
    def build_soa_record(name: str, ttl: int = 3600) -> bytes:
        """构建 SOA 记录（用于权威响应）"""
        # 使用压缩指针（指向问题部分的域名）
        name_bytes = DNSMessage.build_compressed_name()
        mname = DNSMessage.build_domain_name("ns1.example.com")
        rname = DNSMessage.build_domain_name("hostmaster.example.com")

        record = name_bytes
        record += struct.pack('!HHIH', 6, DNS_CLASS_IN, ttl, len(mname + rname + struct.pack('!IIIII', 0, 0, 0, 0, 0)))
        record += mname
        record += rname
        # 序列号、刷新、重试、过期、最小TTL
        record += struct.pack('!IIIII', 2024031701, 3600, 1800, 604800, 300)
        return record


class DomainConfig:
    """域名配置类"""
    def __init__(self):
        self.records: Dict[int, List[str]] = {}  # 记录类型 -> 值列表
        self.special_response: Optional[str] = None  # 特殊响应 (NXDOMAIN, SERVFAIL, REFUSED)
        self.not_response_delay: int = 0  # NOTRESPONSE 延迟时间

    def add_record(self, record_type: int, value: str):
        """添加记录"""
        if record_type not in self.records:
            self.records[record_type] = []
        self.records[record_type].append(value)

    def set_special(self, response: str):
        """设置特殊响应"""
        self.special_response = response

    def set_not_response(self, delay: int = 0):
        """设置不响应"""
        self.special_response = "NOTRESPONSE"
        self.not_response_delay = delay

    def has_record(self, record_type: int) -> bool:
        """检查是否有指定类型的记录"""
        return record_type in self.records and len(self.records[record_type]) > 0

    def get_records(self, record_type: int) -> List[str]:
        """获取指定类型的记录"""
        return self.records.get(record_type, [])


class DoHTestHandler(BaseHTTPRequestHandler):
    """DoH 测试请求处理器"""

    # 域名配置映射
    domain_configs: Dict[str, DomainConfig] = {}

    def log_message(self, format, *args):
        """自定义日志格式"""
        logging.info("%s - %s" % (self.address_string(), format % args))

    def do_GET(self):
        """处理 GET 请求"""
        self.handle_request()

    def do_POST(self):
        """处理 POST 请求"""
        self.handle_request()

    def handle_request(self):
        """统一处理 DoH 请求"""
        try:
            # 检查路径
            if self.path != '/dns-query':
                self.send_error(404, "Not Found")
                return

            # 获取 DNS 请求数据
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                # POST 请求
                dns_query = self.rfile.read(content_length)
            else:
                # GET 请求
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                if 'dns' not in params:
                    self.send_error(400, "Missing DNS parameter")
                    return
                dns_query = base64.urlsafe_b64decode(params['dns'][0] + '==')

            # 记录请求信息
            logging.debug(f"Received DNS query, length: {len(dns_query)} bytes")

            # 解析 DNS 查询
            if len(dns_query) < DNS_HEADER_LENGTH:
                self.send_error(400, "Invalid DNS query")
                return

            query_id = struct.unpack('!H', dns_query[0:2])[0]
            flags = struct.unpack('!H', dns_query[2:4])[0]
            qdcount = struct.unpack('!H', dns_query[4:6])[0]

            logging.debug(f"Query ID: 0x{query_id:04x}, Flags: 0x{flags:04x}, Questions: {qdcount}")

            if qdcount == 0:
                self.send_error(400, "No questions")
                return

            # 解析问题部分
            try:
                domain, qtype, qclass = DNSMessage.parse_question(dns_query)
                qtype_str = {1: "A", 5: "CNAME", 28: "AAAA"}.get(qtype, str(qtype))
                logging.info(f"Query: {domain} (type: {qtype_str}, class: {qclass})")
            except Exception as e:
                logging.error(f"Failed to parse question: {e}")
                self.send_error(400, "Invalid question section")
                return

            # 获取域名配置
            config = self.domain_configs.get(domain)

            # 处理特殊响应
            if config and config.special_response:
                if config.special_response == "NOTRESPONSE":
                    if config.not_response_delay > 0:
                        logging.info(f"NOTRESPONSE configured for {domain} - waiting {config.not_response_delay}s and not responding")
                        time.sleep(config.not_response_delay)
                    logging.info(f"NOTRESPONSE configured for {domain} - not sending any response")
                    return  # 直接返回，不发送任何响应
                elif config.special_response in ["NXDOMAIN", "SERVFAIL", "REFUSED"]:
                    self.send_special_response(dns_query, query_id, domain, config.special_response)
                    return

            # 正常响应 - 完全信任配置文件
            self.send_normal_response(dns_query, query_id, domain, qtype, config)

        except Exception as e:
            logging.error(f"Error handling request: {e}")
            self.send_error(500, "Internal Server Error")

    def send_special_response(self, dns_query: bytes, query_id: int, domain: str, special_type: str):
        """发送特殊响应"""
        rcode_map = {
            "NXDOMAIN": DNS_RCODE_NXDOMAIN,
            "SERVFAIL": DNS_RCODE_SERVFAIL,
            "REFUSED": DNS_RCODE_REFUSED
        }
        rcode = rcode_map.get(special_type, DNS_RCODE_NOERROR)

        # 构建响应头部 - 传递所有6个参数
        response_header = DNSMessage.build_response_header(
            query_id,
            0x8180 | rcode,  # 标准响应 + 错误码
            1,  # qdcount - 问题数（始终为1）
            0,  # ancount - 答案数
            1 if special_type == "NXDOMAIN" else 0,  # nscount - 权威记录数
            0   # arcount - 附加记录数
        )

        response = response_header
        response += dns_query[DNS_HEADER_LENGTH:]  # 回显问题部分

        # 添加权威记录（用于 NXDOMAIN）
        if special_type == "NXDOMAIN":
            soa = DNSMessage.build_soa_record(domain)
            response += soa
            logging.info(f"Added SOA record for NXDOMAIN response")

        # 发送响应
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

        logging.info(f"Sent {special_type} response for {domain}")

    def send_normal_response(self, dns_query: bytes, query_id: int, domain: str, qtype: int, config: Optional[DomainConfig]):
        """发送正常响应 - 完全信任配置文件"""
        # 安全检查：如果是特殊响应，不应该进入这里
        if config and config.special_response:
            logging.error(f"BUG: {domain} has special_response '{config.special_response}' but entered send_normal_response")
            self.send_special_response(dns_query, query_id, domain, config.special_response)
            return

        # 检查是否有匹配的记录
        has_answer = False
        answers = b""
        answer_count = 0

        if config and config.has_record(qtype):
            values = config.get_records(qtype)
            for value in values:
                if qtype == DNS_TYPE_A:
                    try:
                        a_record = DNSMessage.build_a_record(domain, value)
                        answers += a_record
                        answer_count += 1
                        logging.info(f"Returning A record for {domain}: {value}")
                        has_answer = True
                    except Exception as e:
                        logging.error(f"Failed to build A record for {domain}: {value} - {e}")

                elif qtype == DNS_TYPE_AAAA:
                    try:
                        aaaa_record = DNSMessage.build_aaaa_record(domain, value)
                        answers += aaaa_record
                        answer_count += 1
                        logging.info(f"Returning AAAA record for {domain}: {value}")
                        has_answer = True
                    except Exception as e:
                        logging.error(f"Failed to build AAAA record for {domain}: {value} - {e}")

        # 如果有CNAME记录且查询类型不是CNAME，也返回CNAME
        if config and qtype != DNS_TYPE_CNAME and config.has_record(DNS_TYPE_CNAME):
            cname_values = config.get_records(DNS_TYPE_CNAME)
            for cname in cname_values:
                try:
                    cname_record = DNSMessage.build_cname_record(domain, cname)
                    answers += cname_record
                    answer_count += 1
                    logging.info(f"Returning CNAME record for {domain}: {cname}")
                    has_answer = True
                except Exception as e:
                    logging.error(f"Failed to build CNAME record for {domain}: {cname} - {e}")

        # 如果没有任何记录，返回空响应（不设置has_answer）
        if not has_answer:
            logging.info(f"No config for {domain} type {qtype}, returning empty response")

        # 构建响应头部
        response_header = DNSMessage.build_response_header(
            query_id,
            0x8180,  # 标准响应标志
            1,  # qdcount - 问题数
            answer_count,  # 使用实际的答案记录数
            0,  # nscount - 权威记录数
            0   # arcount - 附加记录数
        )

        response = response_header
        response += dns_query[DNS_HEADER_LENGTH:]  # 回显问题部分
        response += answers

        # 发送响应
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

        logging.debug(f"Sent response, length: {len(response)} bytes, answers: {answer_count}")

    def log_error(self, format, *args):
        logging.error(format % args)

def load_config(config_file: str) -> Dict[str, DomainConfig]:
    """加载配置文件 - 正确处理特殊响应和记录类型"""
    domain_configs = {}

    with open(config_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) < 2:
                logging.warning(f"Line {line_num}: Invalid format, need at least 2 parts, skipping")
                continue

            domain = parts[0].rstrip('.')

            # 处理特殊响应（只需要2部分）
            if len(parts) == 2:
                record_type_str = parts[1].upper()

                # 处理 NXDOMAIN/SERVFAIL/REFUSED
                if record_type_str in ["NXDOMAIN", "SERVFAIL", "REFUSED"]:
                    if domain not in domain_configs:
                        domain_configs[domain] = DomainConfig()
                    config = domain_configs[domain]
                    config.set_special(record_type_str)
                    logging.info(f"Config: {domain} -> {record_type_str}")
                    continue

                # 处理 NOTRESPONSE（可能带延迟参数）
                elif record_type_str.startswith("NOTRESPONSE"):
                    delay = 0
                    # 检查是否有 : 分隔的延迟参数
                    if ':' in record_type_str:
                        try:
                            delay = int(record_type_str.split(':')[1])
                        except ValueError:
                            logging.warning(f"Line {line_num}: Invalid delay value in {record_type_str}")

                    if domain not in domain_configs:
                        domain_configs[domain] = DomainConfig()
                    config = domain_configs[domain]
                    config.set_not_response(delay)
                    logging.info(f"Config: {domain} -> NOTRESPONSE (delay: {delay}s)")
                    continue

            # 需要3部分的配置（A/AAAA/CNAME记录）
            if len(parts) < 3:
                logging.warning(f"Line {line_num}: Invalid format for record, need 3 parts, skipping")
                continue

            record_type_str = parts[1].upper()

            # 合并剩余部分作为值，去除注释
            value_parts = parts[2:]
            value_line = ' '.join(value_parts)

            # 去除行内注释（# 后面的内容）
            if '#' in value_line:
                value_line = value_line.split('#')[0].strip()

            value = value_line

            # 获取或创建域名配置
            if domain not in domain_configs:
                domain_configs[domain] = DomainConfig()

            config = domain_configs[domain]

            # 处理记录类型
            if record_type_str in ["A", "AAAA", "CNAME"]:
                record_type = {"A": DNS_TYPE_A, "AAAA": DNS_TYPE_AAAA, "CNAME": DNS_TYPE_CNAME}[record_type_str]
                config.add_record(record_type, value)
                logging.debug(f"Config: {domain} {record_type_str} -> {value}")

            elif record_type_str in ["NXDOMAIN", "SERVFAIL", "REFUSED"]:
                logging.warning(f"Line {line_num}: {record_type_str} should not have value, ignoring")

            elif record_type_str.startswith("NOTRESPONSE"):
                logging.warning(f"Line {line_num}: NOTRESPONSE with value, should be in format 'domain NOTRESPONSE[:delay]'")

            else:
                logging.warning(f"Line {line_num}: Unknown record type {record_type_str}, skipping")

    return domain_configs

def run_server(host: str = 'localhost', port: int = 8053,
               config_file: str = None, ssl: bool = False,
               cert_file: str = None, key_file: str = None):
    """运行 DoH 测试服务器"""

    # 加载配置
    if config_file:
        DoHTestHandler.domain_configs = load_config(config_file)
        logging.info(f"Loaded {len(DoHTestHandler.domain_configs)} domain configurations")
    else:
        # 默认配置
        default_configs = {}

        # IPv4 配置
        ipv4_domains = [
            ('example.com', '123.123.123.123'),
            ('foo.com', '142.250.185.78'),
            ('valid.example', '1.2.3.4'),
            ('invalid-zero.example', '0.0.0.0'),
            ('invalid-loopback.example', '127.0.0.1'),
            ('bing.com', '127.0.0.1'),
            ('invalid-linklocal.example', '169.254.0.0'),
            ('private1.example', '10.10.10.10'),
            ('private2.example', '172.16.16.16'),
            ('private3.example', '192.168.10.10'),
            ('cgnat1.example', '100.64.64.64'),
            ('testnet1.example', '192.0.2.10'),
            ('testnet2.example', '198.51.100.1'),
            ('testnet3.example', '203.0.113.1'),
        ]

        for domain, ip in ipv4_domains:
            if domain not in default_configs:
                default_configs[domain] = DomainConfig()
            default_configs[domain].add_record(DNS_TYPE_A, ip)

        # IPv6 配置
        ipv6_domains = [
            ('ipv6.example', '2001:db8::1234'),
            ('ipv6-loopback.example', '::1'),
            ('ipv6-unspecified.example', '::'),
            ('ipv6-multicast.example', 'ff02::1'),
            ('ipv6-ula.example', 'fc00::1234'),
            ('private4.example', 'fd12:3456:789a::1'),
            ('testnet4.example', '2001:db8:1234::5678'),
        ]

        for domain, ip in ipv6_domains:
            if domain not in default_configs:
                default_configs[domain] = DomainConfig()
            default_configs[domain].add_record(DNS_TYPE_AAAA, ip)

        # 同时支持 A 和 AAAA 的域名
        dual_domains = [
            ('dual.example', DNS_TYPE_A, '1.2.3.4'),
            ('dual.example', DNS_TYPE_AAAA, '2001:db8::1234'),
        ]

        for domain, rtype, ip in dual_domains:
            if domain not in default_configs:
                default_configs[domain] = DomainConfig()
            default_configs[domain].add_record(rtype, ip)

        # 特殊响应配置
        special_domains = [
            ('nxdomain.example', 'NXDOMAIN'),
            ('nonexist.example', 'NXDOMAIN'),
            ('google.com', 'NXDOMAIN'),
            ('servfail.example', 'SERVFAIL'),
            ('google.com.hk', 'SERVFAIL'),
            ('refused.example', 'REFUSED'),
            ('github.com', 'REFUSED'),
        ]

        for domain, special in special_domains:
            if domain not in default_configs:
                default_configs[domain] = DomainConfig()
            default_configs[domain].set_special(special)

        # NOTRESPONSE 配置
        not_response_domains = [
            ('not-response.com', 0),
            ('baidu.com', 8),
            ('timeout5.example', 5),
            ('timeout10.example', 10),
        ]

        for domain, delay in not_response_domains:
            if domain not in default_configs:
                default_configs[domain] = DomainConfig()
            default_configs[domain].set_not_response(delay)

        # CNAME 测试配置
        cname_domains = [
            ('mixture.com', DNS_TYPE_CNAME, 'mixture-cname.example'),
            ('mixture-cname.example', DNS_TYPE_A, '3.173.21.63'),
            ('mixture-cname.example', DNS_TYPE_AAAA, '2001:db8::1'),
        ]

        for domain, rtype, value in cname_domains:
            if domain not in default_configs:
                default_configs[domain] = DomainConfig()
            default_configs[domain].add_record(rtype, value)

        DoHTestHandler.domain_configs = default_configs
        logging.info("Using default configuration")

    # 打印配置摘要
    logging.info("=" * 60)
    logging.info("Domain Configurations Summary:")
    logging.info("=" * 60)
    for domain, config in DoHTestHandler.domain_configs.items():
        if config.special_response:
            if config.special_response == "NOTRESPONSE":
                if config.not_response_delay > 0:
                    logging.info(f"  {domain:30} -> NOTRESPONSE (delay: {config.not_response_delay}s)")
                else:
                    logging.info(f"  {domain:30} -> NOTRESPONSE")
            else:
                logging.info(f"  {domain:30} -> {config.special_response}")
        else:
            records = []
            if DNS_TYPE_A in config.records:
                records.append(f"A:{len(config.records[DNS_TYPE_A])}")
            if DNS_TYPE_AAAA in config.records:
                records.append(f"AAAA:{len(config.records[DNS_TYPE_AAAA])}")
            if DNS_TYPE_CNAME in config.records:
                records.append(f"CNAME:{len(config.records[DNS_TYPE_CNAME])}")
            logging.info(f"  {domain:30} -> {', '.join(records)}")
    logging.info("=" * 60)

    server = HTTPServer((host, port), DoHTestHandler)

    if ssl:
        import ssl
        if not cert_file or not key_file:
            logging.error("SSL requires both cert_file and key_file")
            return
        server.socket = ssl.wrap_socket(
            server.socket,
            certfile=cert_file,
            keyfile=key_file,
            server_side=True
        )
        protocol = "HTTPS"
    else:
        protocol = "HTTP"

    logging.info(f"Starting DoH test server on {protocol}://{host}:{port}/dns-query")
    logging.info("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        server.server_close()


def generate_self_signed_cert():
    """生成自签名证书（用于测试）"""
    try:
        from OpenSSL import crypto
    except ImportError:
        logging.error("OpenSSL module not installed. Please install: pip3 install pyOpenSSL")
        return

    # 生成密钥
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # 生成证书
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)

    # 添加 Subject Alternative Names
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False,
                           b"DNS:localhost, DNS:127.0.0.1, IP:127.0.0.1, DNS:::1, IP:::1"),
    ])

    # 设置有效期
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 365天

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    # 保存
    with open("server.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open("server.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    logging.info("Generated self-signed certificate: server.crt, server.key")
    logging.info("Certificate includes: localhost, 127.0.0.1, ::1")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DoH Test Server')
    parser.add_argument('-H', '--host', default='localhost',
                        help='Host to bind to (default: localhost)')
    parser.add_argument('-p', '--port', type=int, default=8053,
                        help='Port to listen on (default: 8053)')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--ssl', action='store_true',
                        help='Enable HTTPS (requires cert and key)')
    parser.add_argument('--cert', help='SSL certificate file')
    parser.add_argument('--key', help='SSL key file')
    parser.add_argument('--gen-cert', action='store_true',
                        help='Generate self-signed certificate for testing')

    args = parser.parse_args()

    # 设置日志级别
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    if args.gen_cert:
        generate_self_signed_cert()
        exit(0)

    run_server(args.host, args.port, args.config, args.ssl, args.cert, args.key)


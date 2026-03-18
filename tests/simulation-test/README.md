
1. 启动服务器（HTTP模式）
```bash
# 使用默认配置
python3 doh_test_server.py

# 使用配置文件
python3 doh_test_server.py -c doh_test.conf

# 启用详细日志
python3 doh_test_server.py -c doh_test.conf -v
```

2. 生成自签名证书（用于HTTPS测试）
```bash
python3 doh_test_server.py --gen-cert -H <IP or ...>
```

3. 启动HTTPS服务器
```bash
python3 doh_test_server.py --ssl --cert server.crt --key server.key
```

4. 配置 https_dns_proxy 使用测试服务器
```
./https_dns_proxy -r http://127.0.0.1:8053/dns-query -B 8.8.8.8
或者
./https_dns_proxy -f ../https_dns_proxy.conf -v
```

5.测试
```bash
1、nslookup
2、dig baidu.com +noall +answer
```

测试场景
* 有效IP测试：example.com → 123.123.123.123
* 无效IP测试：invalid-zero.example → 0.0.0.0（触发过滤）
* NXDOMAIN测试：nxdomain.example → 触发回退机制
* 服务器错误：servfail.example → 触发回退
* 拒绝响应：refused.example → 触发回退
* 未配置域名：默认返回 123.123.123.123

这个测试服务器完全满足您的需求，可以全面测试 https_dns_proxy 的 IP 过滤和回退机制！


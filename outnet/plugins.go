package outnet

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// 检测dns
func checkDNS(dnsserver, domain string) {
	// 判断是否为远程检测dns
	if okdns {
		// 创建一个Msg
		var msg dns.Msg
		// 调用fqdn将域转换为可以与DNS服务交换的FQDN
		fqdn := dns.Fqdn(domain)
		// fmt.Println(fqdn, dns.TypeA)
		// 设置查询A记录
		msg.SetQuestion(fqdn, dns.TypeA)
		// 将消息发送到DNS服务器
		in, err := dns.Exchange(&msg, dnsserver+":53")
		if err != nil || len(in.Answer) < 1 {
			writeFile("[\033[1;31m✘\033[0m] DNS 协议被阻止", savelog)
			return
		}
	} else {
		// 探测当前主机所有dns出网
		// 设置DNS服务器的地址
		resolver := net.Resolver{
			// PreferGo控制Go的内置DNS解析程序在可用的平台上是否首选
			PreferGo: true,
			// Dial可选择指定一个备用拨号程序，供Go的内置DNS解析程序使用，以建立到DNS服务的TCP和UDP连接
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 1,
				}
				return d.DialContext(ctx, "udp", dnsserver+":53")
			},
		}
		// 解析域名
		resp, err := resolver.LookupHost(context.Background(), domain)
		if err != nil || len(resp) <= 0 {
			writeFile("[\033[1;31m✘\033[0m] DNS 协议被阻止", savelog)
			return
		}
	}
	writeFile("[\033[1;32m✓\033[0m] DNS 协议允许出网", savelog)
}

// 探测http协议出网
func checkHttp(host string) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := 1 * time.Second
	client := http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	resp, err := client.Get("http://" + host)
	if err != nil {
		writeFile("[\033[1;31m✘\033[0m] HTTP 协议被阻止", savelog)
	}
	if resp != nil {
		writeFile("[\033[1;32m✓\033[0m] HTTP 协议允许出网", savelog)
	}
}

// 探测tcp的端口出网情况
func checkTcpall(port string) bool {
	// 如果tcp出网那么allowed_ports_number数量增加
	conn, err := net.DialTimeout("tcp", vps+":"+port, 3*time.Second)
	// 判断端口是否打开
	if err == nil {
		// 关闭连接，减少资源占用
		writeFile("[\033[1;32m✓\033[0m] tcp "+port+" 协议允许出网", savelog)
		conn.Close()
		return true
	}
	return false
}

// 探测其他协议
func checkProtocol(Data ProtocolType) {
	resp := make([]byte, 1024)
	conn, err := net.DialTimeout(Data.Proto, Data.Url, 3*time.Second)
	if err != nil {
		writeFile("[\033[1;31m✘\033[0m] "+Data.Name+" 协议被阻止", savelog)
		return
	}
	if len(Data.Payload) != 0 {
		_, err = conn.Write(Data.Payload)
		if err != nil {
			writeFile("[\033[1;31m✘\033[0m] "+Data.Name+" 协议被阻止", savelog)
			return
		}
	}
	_, err = conn.Read(resp)
	if err != nil {
		writeFile("[\033[1;31m✘\033[0m] "+Data.Name+" 协议被阻止", savelog)
		return
	}
	// fmt.Println(Data.Name, resp, resp[Data.Tag])
	if resp[Data.Tag] == Data.Ok {
		writeFile("[\033[1;32m✓\033[0m] "+Data.Name+" 协议允许出网", savelog)
		return
	} else {
		writeFile("[\033[0;38;5;214m!\033[0m] "+Data.Name+" 协议允许出网，但tag结果不准确", savelog)
	}
}

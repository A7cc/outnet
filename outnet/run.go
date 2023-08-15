package outnet

import (
	"fmt"
)

func Run() {
	// 处理flag
	err := processFile()
	if err != nil {
		fmt.Println("[\033[1;31m✘\033[0m]", err)
		return
	}
	writeFile("[\033[0;38;5;214m!\033[0m] 探测开始", savelog)
	switch mode {
	case "default":
		// 探测dns协议出网
		// 必须有域名
		checkDNS(remotedns, urldomain)
		// 探测http协议出网
		checkHttp(vps)
		// 探测icmp协议出网
		for _, pd := range ProtocolData {
			checkProtocol(pd)
		}
		// 探测TCP协议出网
		checkTcpall(portlists)
	case "alltcp":
		writeFile("[\033[0;38;5;214m!\033[0m] 无输出，表示没有出网的tcp协议端口", savelog)
		// 检测所有端口的tcp
		var slice []int
		for i := 1; i <= 65535; i++ {
			slice = append(slice, i)
		}
		checkTcpall(slice)
	case "deftcp":
		// 探测默认TCP协议出网
		checkTcpall(portlists)
	case "http":
		// 探测http协议出网
		checkHttp(vps)
	case "dns":
		// 探测dns协议出网
		// 必须有域名
		checkDNS(remotedns, urldomain)
	case "tftp":
		for _, p := range ProtocolData {
			if p.Name == "TFTP" {
				// 探测Tftp协议出网
				checkProtocol(p)
			}
		}
	case "ntp":
		for _, p := range ProtocolData {
			if p.Name == "NTP" {
				// 探测Tftp协议出网
				checkProtocol(p)
			}
		}
	case "snmp":
		for _, p := range ProtocolData {
			if p.Name == "SNMP" {
				// 探测Tftp协议出网
				checkProtocol(p)
			}
		}
	case "ssh":
		for _, p := range ProtocolData {
			if p.Name == "SSH" {
				// 探测Tftp协议出网
				checkProtocol(p)
			}
		}
	default:
		fmt.Println("[\033[0;38;5;214m!\033[0m] 出网检测的模式：")
		fmt.Println(" -    default    探测可出网的协议")
		fmt.Println(" -    alltcp     探测所有端口tcp协议")
		fmt.Println(" -    deftcp     探测内置端口tcp协议")
		fmt.Println(" -    http       探测HTTP出网")
		fmt.Println(" -    dns        探测DNS出网")
		fmt.Println(" -    icmp       探测ICMP出网")
		fmt.Println(" -    tftp       探测TFTP出网")
		fmt.Println(" -    ntp        探测NTP出网")
		fmt.Println(" -    snmp       探测SNMP出网")
		fmt.Println(" -    ssh        探测SSH出网")
	}
	writeFile("[\033[0;38;5;214m!\033[0m] 探测结束", savelog)
}

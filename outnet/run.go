package outnet

import (
	"fmt"
	"strconv"
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
		// 设置10000个协程通道
		pool := PoolNew(10000)
		pool.Add(2)
		go func() {
			defer pool.Done()
			// 探测dns协议出网
			// 必须有域名
			checkDNS(remotedns, urldomain)
		}()
		go func() {
			defer pool.Done()
			// 探测http协议出网
			checkHttp(vps)
		}()

		// 探测icmp协议出网
		for _, pd := range ProtocolData {
			pool.Add(1)
			go func(p ProtocolType) {
				defer pool.Done()
				checkProtocol(p)
			}(pd)

		}
		// 存活端口数量
		allowed_ports_number := 0
		// 探测TCP协议出网
		for _, pnum := range portlists {
			pool.Add(1)
			go func(port string) {
				defer pool.Done()
				ok := checkTcpall(port)
				if ok {
					allowed_ports_number += 1
				}
			}(strconv.Itoa(pnum))
			if allowed_ports_number > 3 {
				writeFile("[\033[0;38;5;214m!\033[0m] 发现有3个以上的端口可以访问Internet，中止探测", savelog)
				break
			}
		}
		pool.Wait()
	case "alltcp":
		writeFile("[\033[0;38;5;214m!\033[0m] 无输出，表示没有出网的tcp协议端口", savelog)
		// 设置10000个协程通道
		pool := PoolNew(10000)
		// 存活端口数量
		allowed_ports_number := 0
		// 检测所有端口的tcp
		for i := 1; i <= 65535; i++ {
			pool.Add(1)
			go func(port string) {
				defer pool.Done()
				ok := checkTcpall(port)
				if ok {
					allowed_ports_number++
				}
			}(strconv.Itoa(i))
			if allowed_ports_number > 3 {
				writeFile("[\033[0;38;5;214m!\033[0m] 发现有3个以上的端口可以访问Internet，中止探测", savelog)
				break
			}
		}

		pool.Wait()
	case "deftcp":
		writeFile("[\033[0;38;5;214m!\033[0m] 无输出，表示没有出网的tcp协议端口", savelog)
		// 设置10000个协程通道
		pool := PoolNew(10000)
		// 存活端口数量
		allowed_ports_number := 0
		// 检测所有端口的tcp
		for _, pnum := range portlists {
			pool.Add(1)
			go func(port string) {
				defer pool.Done()
				ok := checkTcpall(port)
				if ok {
					allowed_ports_number += 1
				}
			}(strconv.Itoa(pnum))
			if allowed_ports_number > 3 {
				writeFile("[\033[0;38;5;214m!\033[0m] 发现有3个以上的端口可以访问Internet，中止探测", savelog)
				break
			}
		}
		pool.Wait()
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

package outnet

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"
)

// 处理flag
func processFile() (err error) {
	// 处理flag
	flag.StringVar(&savelog, "o", "output.log", "输出的日志")
	flag.StringVar(&mode, "m", "default", "出网检测的模式，default/alltcp/deftcp/http/dns/icmp/tftp/ntp/snmp/ssh")
	flag.BoolVar(&okdns, "od", false, "只通过指定的dns服务器进行解析")
	flag.StringVar(&vps, "vps", "183.232.231.173", "用于检测http协议的主机")
	flag.StringVar(&remotedns, "rd", "8.8.8.8", "自定义dns服务器")
	flag.StringVar(&urldomain, "ud", "www.baidu.com", "用于dns解析的域名，必须为域名")
	flag.StringVar(&path, "path", "data.json", "设置其他协议配置的路径")
	flag.Parse()
	// 标志
	tagPrint()
	// 检测dns域名合规性
	r := regexp.MustCompile(`[0-9A-Za-z-.]+(\.[a-zA-Z]+)$`)
	num := r.FindStringSubmatch(urldomain)
	if len(num) <= 0 {
		writeFile("[\033[1;31m✘\033[0m] ud参数设置dns解析域名不符合规则，将使用默认域名", savelog)
		urldomain = "www.baidu.com"
	}
	// 读取json
	ProtocolData, err = Readjsonfile(path)
	if err != nil {
		return err
	}
	return nil
}

// 标志
func tagPrint() {
	fmt.Println(`                  __                 __`)
	fmt.Println(`     ____  __ ___/  |_  ____   _____/  |_`)
	fmt.Println(`    /  _ \|  |  \ * __\/    \_/ __ \ ..__\`)
	fmt.Println(`   (  <_> )  |  /|  | |   |  \  ___/|  |`)
	fmt.Println(`    \____/|____/ | _| |___|__/\_____>_ |`)
	fmt.Printf("                 |/ version: %-8s \\|\n", version)
	fmt.Println()
}

// 文件写入
func writeFile(result string, filename string) {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("[\033[31;1m-\033[0m] 打开文件 %s 失败, %v\n", filename, err)
		return
	}
	defer f.Close()

	io.Copy(io.MultiWriter(os.Stdout, f), strings.NewReader(result+"\n"))
}

// 读取json文件
func Readjsonfile(filename string) ([]ProtocolType, error) {
	// 设置json文件
	var jsonlist []ProtocolType
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &jsonlist)
	if err != nil {
		return nil, err
	}
	return jsonlist, nil
}

// New 新建一个协程池
func PoolNew(size int) *Pool {
	if size <= 0 {
		size = 1
	}
	return &Pool{
		queue: make(chan int, size),
		wg:    &sync.WaitGroup{},
	}
}

// Add 新增一个执行
func (p *Pool) Add(delta int) {
	// delta为正数就添加
	for i := 0; i < delta; i++ {
		p.queue <- 1
	}
	// delta为负数就减少
	for i := 0; i > delta; i-- {
		<-p.queue
	}
	p.wg.Add(delta)
}

// Done 执行完成减一
func (p *Pool) Done() {
	<-p.queue
	p.wg.Done()
}

// 等待全部协程结束
func (p *Pool) Wait() {
	p.wg.Wait()
}

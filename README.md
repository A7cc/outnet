# 壹 介绍

该工具能通过各种协议去检测当前主机出网情况。目前该工具支持的协议有：`http`、`dns`、`icmp`、`tftp`、`ntp`、`snmp`

探测协议出网的原理主要是通过构造对应协议的数据包进行检测，当然这些请求数据包可以进行自定义。

# 贰 参数

![image-20230815101129225](images\image-20230815101129225.png)

|  参数   | 参数说明                                                     |  类型  |
| :-----: | ------------------------------------------------------------ | :----: |
|  `-m`   | 出网检测的模式，该参数是通过不同协议进行探测                 | string |
|  `-o`   | 输出的日志                                                   | string |
|  `-od`  | 只通过指定的dns服务器进行解析，假设在域环境里，域控允许出网，该主机不允许出网，这时候如果我们不设置该参数，那么就会通过本机所有的dns和自定义的dns服务器进行探测出网 |  bool  |
| `-path` | 设置其他协议配置的路径                                       | string |
|  `-rd`  | 自定义dns解析服务器                                          | string |
|  `-ud`  | 用于dns解析的域名，必须为域名，否则不会进行域名解析          | string |
| `-vps`  | 用于检测http协议的主机                                       | string |

出网检测的模式：

![image-20230815133321330](images\image-20230815133321330.png)



# 叁 使用

- 编译

```bash
# windows
go build -o outnet_winodws_amd64.exe -ldflags="-s -w" -trimpath .
# linux
go build -o outnet_linux_amd64 -ldflags="-s -w" -trimpath .
# macOS
go build -o outnet_darwin_amd64 -ldflags="-s -w" -trimpath .
```

- 帮助`-h`

![image-20230815133306224](images\image-20230815133306224.png)

- 默认模式检测

![image-20230815133428694](images\image-20230815133428694.png)

- 指定模式检测

![image-20230815133537329](images\image-20230815133537329.png)

- 只检测指定的dns服务器，假设在域环境里，域控允许出网，该主机不允许出网，这时候如果我们不设置该参数，那么就会通过本机所有的dns和自定义的dns服务器进行探测出网

![image-20230815133817894](images\image-20230815133817894.png)



# 肆 参考

- [Golang实现获取SNMP V3数据](https://www.cnblogs.com/feng0919/p/15760915.html)
- [TFTP协议（基于UDP）](https://blog.csdn.net/PPPPPPPKD/article/details/124446574)
- [DNS基础知识以及golang实现的简单DNS服务器](https://blog.csdn.net/i_19970916/article/details/123108679)
- [ntp服务器udp协议,golang实现NTP协议获取服务器时间[通俗易懂]](https://cloud.tencent.com/developer/article/2125443)
- [IP、ICMP、TCP和UDP校验和计算](https://blog.csdn.net/to_be_better_wen/article/details/129191378)
- [ICMP协议详解](https://www.yii666.com/blog/360594.html)
- [使用 Golang 实现 SSH 隧道功能](https://segmentfault.com/a/1190000040246792?sort=votes)
# 识别方法
## 1. 基于域名解析的IP地址数量
  通常情况，一个域名不会对应太多的IP地址，如果存在一个域名对应多个IP的情况，则可能是使用了CDN技术；反之，如果只能解析到一个IP，则大概率未采用CDN技术。
```
    > www.baidu.com
    Server:		10.33.93.1
    Address:	10.33.93.1#53
    
    Non-authoritative answer:
    www.baidu.com	canonical name = www.a.shifen.com.
    Name:	www.a.shifen.com
    Address: 183.232.231.174
    Name:	www.a.shifen.com
    Address: 183.232.231.172
    > www.qq.com
    Server:		10.33.93.1
    Address:	10.33.93.1#53
    
    Non-authoritative answer:
    www.qq.com	canonical name = ins-r23tsuuf.ias.tencent-cloud.net.
    Name:	ins-r23tsuuf.ias.tencent-cloud.net
    Address: 112.53.42.114
    Name:	ins-r23tsuuf.ias.tencent-cloud.net
    Address: 112.53.42.52
> ```
  java代码层面，可使用以下代码进行判断
```java
String domainName = "www.baidu.com";
for(InetAddress inetAddress:InetAddress.getAllByName(domainName)){
    System.out.println(inetAddress.getHostAddress());
}
```
## 2. 基于header里的字段识别

## 3. 基于多地ping

# 实现流程


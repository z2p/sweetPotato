package burp.Bootstrap;

import java.net.URL;
import java.io.PrintWriter;
import java.net.MalformedURLException;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IBurpExtenderCallbacks;

public class CustomBurpUrl {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse messageInfo;

    public CustomBurpUrl(IBurpExtenderCallbacks callbacks, IHttpRequestResponse messageInfo) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.messageInfo = messageInfo;
    }

    /**
     * 获取协议，哪怕发送失败也可以拿到
     * @param messageInfo
     * @return
     */
    public static String getRequestProtocol(IHttpRequestResponse messageInfo) {
        return messageInfo.getHttpService().getProtocol();
    }

    public static String getRequestProtocol(String url){
        if (url.startsWith("https://")) return "https";
        if (url.startsWith("http://")) return "http";

        return "http";
//        throw new Exception("提供的url不符合http协议标准");
    }



    /**
     * 获取-请求主机，哪怕发送失败也可以拿到
     *
     * @return
     */
    public static String getRequestHost(IHttpRequestResponse messageInfo) {
        return messageInfo.getHttpService().getHost();
    }

    /**
     * 获取-请求端口，哪怕发送失败也可以拿到
     *
     * @return
     */
    public static int getRequestPort(IHttpRequestResponse messageInfo) {
        return messageInfo.getHttpService().getPort();
    }

    public static int getRequestPort(String url){

        int port = 0;
        String tempUrl = url.replace("https://","").replace("http://","");

        if(tempUrl.contains(":")){
            port = Integer.parseInt(url.split(":")[2]);
        }
        else{
            if(url.startsWith("https://")) port = 443;
            if(url.startsWith("http://")) port = 80;
        }
        return port;
    }

    /**
     * 获取-请求路径，哪怕发送失败也可以拿到
     *
     * @return
     */
    public static String getRequestPath(IHttpRequestResponse messageInfo,IExtensionHelpers helpers) {
        return helpers.analyzeRequest(messageInfo).getUrl().getPath();
    }

    /**
     * 访问的文件后缀
     * @return
     */
    public String getFileSuffix(){
        if(getRequestPath(messageInfo,helpers).contains(".")){
            String[] temp = getRequestPath(messageInfo,helpers).split("\\.");
            return temp[temp.length-1];
        }
        else{
            return "";
        }
    }

    /**
     * 获取-请求参数，哪怕发送失败也可以拿到
     *
     * @return
     */
    public static String getRequestQuery(IHttpRequestResponse messageInfo,IExtensionHelpers helpers) {
        return helpers.analyzeRequest(messageInfo).getUrl().getQuery();
    }

    /**
     * 获取-请求域名名称，哪怕发送失败也可以拿到 http://xxxxx:xxx
     *
     * @return
     */
    public static String getRequestDomainName(IHttpRequestResponse messageInfo) {
        // 获取端口号
        int port = getRequestPort(messageInfo);
        // 拼接
        String requestDomainName = getRequestProtocol(messageInfo) + "://" + getRequestHost(messageInfo);
        // 如果不是80或443，在后面加上端口号
        if(port != 80 && port != 443){
            requestDomainName += ":" + port;
        }
        return requestDomainName;
    }

    /**
     * 提供 http://xxxx.xxx:8080/xxxxxx 返回 http://xxxx.xxxx:8080
     * @param requestsUrl
     * @return
     */
    public static String getRequestDomainName(String requestsUrl){

        String prefix = "";
        String requestDomainName = "";
        String temp = "";
        if(requestsUrl.contains("https://")){
            prefix = "https";
        }
        else if(requestsUrl.contains("http://")){
            prefix = "http";
        }

        temp = requestsUrl.replace("http://","").replace("https://","");
        if(temp.contains("/")){
            temp = temp.split("/")[0];
        }
        requestDomainName = prefix + "://" + temp;
        return requestDomainName;
    }

    /**
     * 获取-获取http请求url，发送失败也可以获取，获取到url完整路径，如 http://xxxx.com/index.php?ia=d2&aa=123
     *
     * @return
     */
    public static URL getHttpRequestUrl(IHttpRequestResponse messageInfo,IExtensionHelpers helpers) {

        String url = getRequestDomainName(messageInfo) + getRequestPath(messageInfo,helpers);
        if (getRequestQuery(messageInfo,helpers) != null){
            url += "?" + getRequestQuery(messageInfo,helpers);
        }
        try{
            return new URL(url);
        }catch (MalformedURLException e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param host httpResponse里的host
     * @return xxx.com
     */
    public static String getDomain(String host){
        String domain = host.replace("https://","").replace("http://","");
        if (domain.contains(":")){
            domain = domain.split(":")[0];
        }
        if(domain.contains("/")){
            domain = domain.split("/")[0];
        }
        return domain;
    }

}
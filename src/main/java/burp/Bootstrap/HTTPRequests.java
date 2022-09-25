package burp.Bootstrap;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;

import java.util.List;

public class HTTPRequests {

    List<IParameter> parameterList;
    String key; // 唯一值
    String url; // url fqdn 如：http://xxx.baidxx.com/asdsads/ddd.jsp
    String host; // host 如：http://xxxx.com
    String domain; // domain 如： xxx.com 或 111.111.111.111
    byte contentType;
    byte[] byteRequestsRaw; // 请求完整报文

    public HTTPRequests(IBurpExtenderCallbacks callbacks, IHttpRequestResponse messageInfo){

        this.byteRequestsRaw = messageInfo.getRequest();
        this.parameterList = callbacks.getHelpers().analyzeRequest(byteRequestsRaw).getParameters();
        this.key = callbacks.getHelpers().analyzeRequest(byteRequestsRaw).toString();
        this.url = CustomBurpUrl.getHttpRequestUrl(messageInfo, callbacks.getHelpers()).toString();
        this.host = CustomBurpUrl.getRequestDomainName(messageInfo);
        this.domain = CustomBurpUrl.getDomain(host);
        this.contentType = callbacks.getHelpers().analyzeRequest(byteRequestsRaw).getContentType();
    }

    public byte getContentType() {
        return contentType;
    }

    public String getUrl() {
        return url;
    }

    public String getHost() {
        return host;
    }

    public String getDomain() {
        return domain;
    }

    public byte[] getByteRequestsRaw() {
        return byteRequestsRaw;
    }

    public String getKey(){
        return key;
    }

    public List<IParameter> getParameterList() {
        return parameterList;
    }
}

package burp.Bootstrap;

import burp.*;
import burp.Controller.ProjectController;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class BurpSuiteRequests {

    /**
     *
     * @param url
     * @param headers
     * @param callbacks
     * @param allow_redirects
     * @param config
     *
     * @return
     */
    public static IHttpRequestResponse get(String url, List<String> headers, IBurpExtenderCallbacks callbacks, boolean allow_redirects, Config config,int redirect_count){

        IHttpRequestResponse messageInfo = null;
        IExtensionHelpers helpers = callbacks.getHelpers();
        ArrayList<String> newHeaders = new ArrayList<String>();

        try {
            // 创建url对象
            URL scanUrl = new URL(url);
            // 获取端口号
            int port = scanUrl.getPort() == -1? scanUrl.getDefaultPort() : scanUrl.getPort();
            // 如果用户传递的headers为null，则自己创建一个
            if(headers == null){
                newHeaders.add("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0");
            }
            else{
                for(String header:headers){
                    newHeaders.add(header);
                }
            }

            // 往前方添加请求行
            if(scanUrl.getQuery() != null && scanUrl.getQuery().length() > 0){
                newHeaders.add(0,String.format("GET %s?%s HTTP/1.1",scanUrl.getPath(),scanUrl.getQuery()));
            }
            else{
                String path;
                if(scanUrl.getPath().length() == 0){
                    path = "/";
                }
                else{
                    path = scanUrl.getPath();
                }
                newHeaders.add(0,String.format("GET %s HTTP/1.1",path));
            }

            // 添加目标host字段
            if(port == 80 || port == 443){
                newHeaders.add(1,String.format("Host: %s",scanUrl.getHost()));
            }
            else{
                newHeaders.add(1,String.format("Host: %s:%d",scanUrl.getHost(),port));
            }

            // 创建service
            IHttpService service = helpers.buildHttpService(scanUrl.getHost(), port, scanUrl.getProtocol());
            // 生成数据包
            byte[] requestsRaw = helpers.buildHttpMessage(newHeaders,new byte[0]);
            // 发送数据
            messageInfo = callbacks.makeHttpRequest(service,requestsRaw);
            // 生成内部的httpResponse
            HTTPResponse httpResponse = new HTTPResponse(callbacks,messageInfo);
            // 提供给到项目管理分析，是否要加入一些任务到队列里进行消费
            ProjectController.analysisNeedScanLinkAndAdd(config.getTags().getProjectTableTag().getUrlHashSet(), config.getTags().getProjectTableTag().getTargetHashSet(), config.getProjectManagerUrls(),httpResponse);

            // 以下逻辑 应用于判断是否要进行302跳转
            int statusCode = httpResponse.getStatus();
            if((statusCode == 302 || statusCode == 301) && allow_redirects && httpResponse.getHeaders().containsKey("Location") && redirect_count > 0){
                // 提取一下location
                String location = httpResponse.getHeaders().get("Location").toString().replace("HTTPS://","https://").replace("HTTP://","http://");
                // 判断一下是相对路径，还是绝对路径
                // 说明是绝对路径，可以跳转访问
                String newLocation = "";
                // 如果跳转的链接和当前的url是完全一样，那就不进行访问
                if (location.equals(url) || location.trim().length() < 1){ }
                else if(location.startsWith("http://") || location.startsWith("https://")){
                    newLocation = location;
                }
                else if(location.startsWith("//")){
                    newLocation = "http:" + location;
                }
                else if(location.startsWith("/")){
                    newLocation = httpResponse.getHost() + location;
                }
                else{
                    System.out.println("Location是相对路径，需要研究一下！！！" + location);
                }

                // 如果location为空，那就不进行访问了
                if(newLocation.length() != 0){
                    get(newLocation,headers,callbacks,allow_redirects,config,redirect_count-1);
                }
            }

        } catch (RuntimeException e){
            System.out.println(String.format("[-] %s 无法访问",url));
        } catch (Exception e){
            e.printStackTrace();
        }

        return messageInfo;
    }

    public static IHttpRequestResponse post(String url,List<String> headers,String body,IBurpExtenderCallbacks callbacks){

        IHttpRequestResponse messageInfo = null;
        IExtensionHelpers helpers = callbacks.getHelpers();
        ArrayList<String> newHeaders = new ArrayList<String>();

        try{
            // 创建url对象
            URL scanUrl = new URL(url);
            // 获取端口号
            int port = scanUrl.getPort() == -1? scanUrl.getDefaultPort() : scanUrl.getPort();
            // 如果用户传递的headers为null，则自己创建一个
            if(headers == null){
                newHeaders.add("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0");
            }

            // 往前方添加请求行和host字段
            if(scanUrl.getQuery().length() > 0){
                newHeaders.add(0,String.format("POST %s?%s HTTP/1.1",scanUrl.getPath(),scanUrl.getQuery()));
            }
            else{
                newHeaders.add(0,String.format("POST %s HTTP/1.1",scanUrl.getPath()));
            }
            newHeaders.add(1,String.format("Host: %s:%d",scanUrl.getHost(),port));
            for(String header:headers){
                newHeaders.add(header);
            }
            // 创建service
            IHttpService service = helpers.buildHttpService(scanUrl.getHost(), port, scanUrl.getProtocol());
            // 生成数据包
            byte[] requestsRaw = helpers.buildHttpMessage(newHeaders,body.getBytes(StandardCharsets.UTF_8));
            // 发送数据
            messageInfo = callbacks.makeHttpRequest(service,requestsRaw);

        } catch (Exception e){
            e.printStackTrace();
        }

        return messageInfo;
    }

    public static IHttpRequestResponse rawDemo(String url,String requestsDemo,IBurpExtenderCallbacks callbacks){

        IHttpRequestResponse messageInfo = null;
        IExtensionHelpers helpers = callbacks.getHelpers();

        try{
            // 创建url对象
            URL scanUrl = new URL(url);
            // 获取端口号
            int port = scanUrl.getPort() == -1? scanUrl.getDefaultPort() : scanUrl.getPort();
            // 创建service
            IHttpService service = helpers.buildHttpService(scanUrl.getHost(), port, scanUrl.getProtocol());
            // 生成数据包
            byte[] requestsRaw = formatHost(requestsDemo,scanUrl).getBytes(StandardCharsets.UTF_8);
            // 发送数据
            messageInfo = callbacks.makeHttpRequest(service,requestsRaw);

        } catch (Exception e){
            e.printStackTrace();
        }

        return messageInfo;
    }

    public static IHttpRequestResponse raw(String url,byte[] requestsRaw,IBurpExtenderCallbacks callbacks){

        IHttpRequestResponse messageInfo = null;
        IExtensionHelpers helpers = callbacks.getHelpers();

        try{
            // 创建url对象
            URL scanUrl = new URL(url);
            // 获取端口号
            int port = scanUrl.getPort() == -1? scanUrl.getDefaultPort() : scanUrl.getPort();
            // 创建service
            IHttpService service = helpers.buildHttpService(scanUrl.getHost(), port, scanUrl.getProtocol());
            // 发送数据
            messageInfo = callbacks.makeHttpRequest(service,requestsRaw);

        } catch (Exception e){
            e.printStackTrace();
        }

        return messageInfo;
    }

    /**
     * 对Host字段进行格式化
     * @param requestsDemo
     * @param scanURL
     * @return
     */
    public static String formatHost(String requestsDemo,URL scanURL){
        int port = 0;
        String requestsRaw = "";
        if(scanURL.getPort() == -1){
            port = scanURL.getDefaultPort();
        }
        else{
            port = scanURL.getPort();
        }
        // 增加了异常处理，有一些不是很合适format，因为一个报文会有很多%
        try {
            requestsRaw = String.format(requestsDemo, scanURL.getHost() + ":" + port);
        } catch (Exception e){
            requestsRaw = requestsDemo.replace("aaaaabbbbbccccc",scanURL.getHost() + ":" + port);
        }

        return requestsRaw;
    }
}

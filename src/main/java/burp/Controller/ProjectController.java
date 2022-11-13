package burp.Controller;

import burp.Bootstrap.*;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.Ui.Tags;

import java.util.*;
import java.util.concurrent.Callable;

public class ProjectController implements Callable<String> {

    private Config config;
    private Vector<String> urls;  // 剩余需要访问的url
    private String name;
    private HashSet<String> targetHashSet;
    private Set<String> urlHashSet;
    private Tags tags;
    private IBurpExtenderCallbacks callbacks;
    final long sleepTime = 5000;    // 线程睡眠时间，当没任务 或 用户暂停都会触发，默认为5秒

    public ProjectController(Config config,String name){
        // 变量初始化
        this.name = name;
        this.config = config;
        this.urls = config.getProjectManagerUrls();
        this.targetHashSet = config.getTags().getProjectTableTag().getTargetHashSet();
        this.urlHashSet = config.getTags().getProjectTableTag().getUrlHashSet();
        this.tags = config.getTags();
        this.callbacks = config.getCallbacks();
    }

    public void run(){

        config.getStdout().println("[" + name + "] ID: " + this.hashCode()+ "\t启动了！");
        a:
        while(true){
            // 当用户卸载掉插件后，要关闭所有线程，退出循环
            if(config.isExtensionUnload()){
                config.getStdout().println("[" + name + "] ID: " + this.hashCode()+ "\t用户关闭了插件，终止线程！");
                // 清空掉全局vector
                urls.clear();
                // 将所有线程结束，直到重新加载为止
                break a;
            }

            // 访问httpResponses，看里面是否有数据；有数据，取；无数据，休眠5秒
            if(urls.size() == 0) {
                try{
                    Thread.sleep(sleepTime);
                } catch (Exception e){
                    e.printStackTrace();
                }
                continue;
            }

            // 当用户勾选暂停后，
            if(config.getTags().getProjectTableTag().getRecursionCheckBox().isSelected()){
                try{
                    Thread.sleep(sleepTime);
                }catch (Exception e){
                    e.printStackTrace();
                };
                continue;
            }

            // 取数据和分析
            String scanUrl = urls.remove(0);
            config.getStdout().println("[" + name + "] ID: " + this.hashCode()+ "\t当前准备访问:" + scanUrl);
            // 不需要遍历了，直接将这些url进行访问，然后再解析，再评估哪一些要放到vector供下次扫描使用
            uncontainUrlFlow(scanUrl);
        }
    }

    /**
     *
     * @param host host和url是一样的，都是 http://xxxxx.com:8080 这种格式
     */
    public void uncontainUrlFlow(String host){

        // 立刻先更新到urlHashSet
        urlHashSet.add(host);
        // 定义一个新的httpresponse
        HTTPResponse newHTTPResponse = null;
        IHttpRequestResponse newMessageInfo = null;

        newMessageInfo = BurpSuiteRequests.get(host, null, callbacks,true,config,5);

        // 如果访问目标出现了失败，可能是什么情况？ 例如：http://www.baidu.com 上存在一个链接 http://qq.baidu.com，该链接已经无法访问
        if (newMessageInfo == null || newMessageInfo.getResponse() == null) {
            newHTTPResponse = new HTTPResponse(host);
            // 如果当前访问是异常，那对内容做一个初始化，做一些exception
            newMessageInfo = new IHttpRequestResponse() {
                @Override
                public byte[] getRequest() {
                    return "link exception".getBytes();
                }

                @Override
                public void setRequest(byte[] message) {

                }

                @Override
                public byte[] getResponse() {
                    return "link exception".getBytes();
                }

                @Override
                public void setResponse(byte[] message) {

                }

                @Override
                public String getComment() {
                    return null;
                }

                @Override
                public void setComment(String comment) {

                }

                @Override
                public String getHighlight() {
                    return null;
                }

                @Override
                public void setHighlight(String color) {

                }

                @Override
                public IHttpService getHttpService() {
                    return null;
                }

                @Override
                public void setHttpService(IHttpService httpService) {

                }
            };
        }
        else {
            newHTTPResponse = new HTTPResponse(callbacks, newMessageInfo);
        }

        // 将内容调用一次被动分析的流程，如果状态码为-1，说明是异常，当不为-1时才做被动分析；现在做被动的原因，因为要去修改finger的内容，这样表格入库才会更新数据
        if (newHTTPResponse.getStatus() != -1) {
            HTTPRequests newHTTPRequests = new HTTPRequests(callbacks, newMessageInfo);
            new VulnsController().passiveScanController(newHTTPRequests, newHTTPResponse, newMessageInfo, tags, config);
            // 增加主动分析的流程
            new VulnsController().activeScanController(newHTTPRequests,newHTTPResponse,tags,config);
        }

        // 下面是准备做入库的逻辑
        // 判断是否为IP
        if(newHTTPResponse.isIP(newHTTPResponse.getDomain())){
            // 如果是ip，表示getDomain也是IP，不用转化可以直接用了
            newHTTPResponse.setIp(newHTTPResponse.getDomain());
        }
        else{
            // 如果不是ip，说明是域名，要转化成IP
            newHTTPResponse.setIp(HTTPResponse.getIP(newHTTPResponse.getDomain()));
        }

        // 这里的add函数做了修改，会自动入库
        tags.getProjectTableTag().add(
                newHTTPResponse,
                newMessageInfo
        );

        // 分析访问过的页面，存在哪些新的链接需要扫描，将这些需要扫描的目标，加入到set和vector里
        analysisNeedScanLinkAndAdd(urlHashSet,targetHashSet, config.getProjectManagerUrls(), newHTTPResponse);
    }

    /**
     * 分析当前的httpResponse里提取出来的链接，在当前用户配置的【目标管理】里，结合历史扫描过的任务，判断哪些是需要进行扫描的
     * @param urlHashSet            加载插件之后，所有访问过的历史数据链接存储为止，用来判断当前目标是否历史扫描过
     * @param targetHashSet         每个项目，大家填写的关键根域名
     * @param projectManagerUrls    待消费的队列
     * @param httpResponse          访问后得到的Response类
     */
    public static void analysisNeedScanLinkAndAdd(Set<String> urlHashSet,HashSet<String> targetHashSet,Vector<String> projectManagerUrls,HTTPResponse httpResponse){

        // 分析当前页面，提取出所有链接
        HashSet<String> currentAllLinks = httpResponse.getAllLinks(httpResponse.getStrBody(), httpResponse.getHeaders(),httpResponse.getResponseRaw(),httpResponse.getHost());

        // 遍历【目标管理】
        for(String domain:targetHashSet){
            HashSet<String> sameDomainUrls = HTTPResponse.getSameDomainLinks(currentAllLinks,domain);
            for(String url:sameDomainUrls) {
                if (url.trim().length() == 0) continue;
                // 判断一下这些url是否在set里了，如果在，那就不要加到任务池；如果不在，那就加到set里，并且加到任务池
                if(!urlHashSet.contains(url)){
                    urlHashSet.add(url);
                    projectManagerUrls.add(url);
                }
            }

            // 页面里提取出来的所有域名，用来做一些补充，例如页面里会有 "www.baidu.com"，这一类的也能收集到
            HashSet<String> responseDomain = httpResponse.getResponseDomain();
            for(String eachDomain:responseDomain){
                if(eachDomain.startsWith(".")) continue;
                String newUrl = "http://" + eachDomain;
                if(eachDomain.endsWith(domain) && !urlHashSet.contains(newUrl)){
                    urlHashSet.add(newUrl);
                    projectManagerUrls.add(newUrl);
                }
            }
        }
    }

    @Override
    public String call() throws Exception {
        run();
        return null;
    }

}

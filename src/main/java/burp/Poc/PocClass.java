package burp.Poc;

import burp.Bootstrap.*;
import burp.Controller.VulnsController;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.Ui.Tags;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public abstract class PocClass {

    public static int REMATCH_PLACE_BODY = 1;           // 根据body进行关键字匹配
    public static int REMATCH_PLACE_HEADER = 2;         // 根据header进行关键字匹配
    public static int REMATCH_PLACE_ALL = 3;            // 根据整个响应报文进行关键字匹配

    public PocInfo pocInfo;
    public String target;
    public String pocName;
    public String level;
    public Tags tags;
    public Config config;
    public String showUserPocName;
    public IBurpExtenderCallbacks callbacks;
    public List<String> headers;
    // 以下为初始化的参数，若后面没修改，则会展示给用户
    public String title = "exception";
    public String server = "exception";
    public int length = 0;
    public int status = 0;

    public PocClass(PocInfo pocInfo){
        this.pocInfo = pocInfo;
        this.target = pocInfo.getTarget();
        this.pocName = pocInfo.getPocName();
        this.level = pocInfo.getLevel();
        this.tags = pocInfo.getTags();
        this.config = pocInfo.getConfig();
        this.showUserPocName = pocInfo.getShowUserPocName();
        this.callbacks = config.getCallbacks();
        this.headers = new ArrayList<String>();
        // 初始化，增加一个User-Agent的头部信息
        this.headers.add("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0");
        System.out.println("当前进入Poc：" + this.showUserPocName + "\n" + "目标：" + this.target);
    }

    public void showUserParaLoad(HTTPResponse httpResponse){
        title = httpResponse.getTitle();
        server = httpResponse.getServer();
        length = httpResponse.getLength();
        status = httpResponse.getStatus();
    }

    public void showUserParaException(){
        title = "Exception";
        server = "Exception";
        length = -1;
        status = -1;
    }

    public abstract void check();

    /**
     * 对请求结果进行分析和处理，并将内容展示界面 和 给到被动扫描等，调用后，还是会把输入继续输出
     * @param messageInfo
     * @param re_match 可以为null
     */
    public IHttpRequestResponse check(IHttpRequestResponse messageInfo,String re_match,int rematch_place){

        // 1、先生成requests对象
        HTTPRequests httpRequests = new HTTPRequests(config.getCallbacks(),messageInfo);
        // 2、先更新sitemap
        callbacks.addToSiteMap(messageInfo);
        try{
            // 3、如果没response，则直接返回
            if(messageInfo.getResponse() == null){
                showUserParaException();
                return messageInfo;
            }
            // 4、生成Httpresponse
            HTTPResponse httpResponse = new HTTPResponse(config.getCallbacks(),messageInfo);
            // 5、填充字段
            showUserParaLoad(httpResponse);
            // 6、先给到被动分析进行处置
            new VulnsController().passiveScanController(httpRequests,httpResponse,messageInfo,tags,config);
            // 7、如果不需要匹配关键字，就可以返回了
            if(re_match == null){
                return messageInfo;
            }

            // 模式1：为只匹配body内容，忽略大小写
            if (rematch_place == 1){
                if(httpResponse.getStrBody().toLowerCase(Locale.ROOT).contains(re_match.toLowerCase(Locale.ROOT))){
                    // 填写到脆弱性表格
                    Tools.addInfoToVulnTags(config,tags,httpResponse,"存在漏洞:"+showUserPocName,level,httpResponse.getHost() + ":" + showUserPocName,messageInfo);
                }
            }
            // 模式2：为匹配header内容，忽略大小写
            else if(rematch_place == 2){
                for(Map.Entry<String, Object> entry: httpResponse.getHeaders().entrySet()){
                    if(entry.getValue().toString().toLowerCase(Locale.ROOT).contains(re_match.toLowerCase(Locale.ROOT))){
                        // 填写到脆弱性表格
                        Tools.addInfoToVulnTags(config,tags,httpResponse,"存在漏洞:"+showUserPocName,level,httpResponse.getHost() + ":" + showUserPocName,messageInfo);
                    }
                }
            }
            else if(rematch_place == 3){

            }

        } catch (Exception e){
            e.printStackTrace();
        } finally {
            // 最终写到界面上，url做了解码
            config.getTags().getPocTag().add(Tools.URLDecoderString(httpRequests.getUrl()), httpRequests.getHost(), showUserPocName, title, server, length, status, messageInfo);
        }

        return messageInfo;
    }
}

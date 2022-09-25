package burp;
import java.text.SimpleDateFormat;
import java.util.*;
import java.io.PrintWriter;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import burp.Bootstrap.*;
import burp.Controller.*;
import burp.Ui.*;

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory, IExtensionStateListener,IScannerCheck {

    public static String NAME = "Sweet Potato"; // 插件名称
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Tags tags;
    private Config config;
    private TagPopMenu tagPopMenu;
    final int threadNum = 10;   // 项目里的线程数量，默认10个

    /**
     * 关键函数，bp调用入口
     * @param callbacks
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.config = new Config();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        // 表格右键公用菜单
        this.tagPopMenu = new TagPopMenu();
        // helper和callback存储
        config.setHelpers(callbacks.getHelpers());
        config.setCallbacks(callbacks);
        config.setJarPath(Tools.getExtensionFilePath(callbacks));

        // 标签界面
        this.tags = new Tags(callbacks, NAME,config);

        // 设置扩展名称
        callbacks.setExtensionName(NAME);
        // 注册http监听器
        callbacks.registerHttpListener(this);
        // 注册新标签页的工厂，主要是给已有功能模块增加tab页面用的
        callbacks.registerMessageEditorTabFactory(this);
        // 注册监听插件卸载的情况
        callbacks.registerExtensionStateListener(this);
        // 注册扫描监听器
        callbacks.registerScannerCheck(this);

        // 全局面板的状态做初始化
        this.tags.getMain2Tag().getStatus().setText("当前状态：指纹成功加载 " + config.getFingerJsonInfo().size() + "条");
        // 为项目管理的模块创建线程池，死循环监听和执行
        projectThreadManager(threadNum);
    }

    /**
     * 为项目管理的模块创建线程池，死循环监听和执行
     */
    public void projectThreadManager(int threadNum){

        // 1、起一个线程单独更新任务数量展示
        new Thread(new BackGroundProjectCountThread(config)).start();
        // 2、起一个线程把IP类的任务给放入
        new Thread(new ProjectIPThread(config)).start();

        // 2、将我们定义好的线程类给放进来，根据定义的数量来创建for循环
        ExecutorService executorService = Executors.newFixedThreadPool(threadNum);
        for(int i=0;i<threadNum;i++){
            executorService.submit(new ProjectController(config,"线程"+i));
        }
        executorService.shutdown();
    }

    /**
     * http proxy监听器，所有流量都会到该函数
     * @param toolFlag
     * @param messageIsRequest
     * @param messageInfo
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        Main2Tag main2Tag = this.tags.getMain2Tag();
        byte[] newResponse = messageInfo.getResponse();
        byte[] newRequests = messageInfo.getRequest();

        // 可以增加url黑白名单的过滤
        // 可以增加文件类型的过滤

        // toolFlag设置只保留一部分模块的流量引入，如：proxy、repeater、扩展程序的流量
        if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY && toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER) {
            return;
        }

        // 如果是请求，按请求逻辑走
        if (messageIsRequest){
            HTTPRequests httpRequests = new HTTPRequests(this.callbacks, messageInfo);
            List<String> requestsHeaders = this.helpers.analyzeRequest(newRequests).getHeaders();

            // 是否要增加shiro到cookie中
            if (main2Tag.getAddRememberMeButton().isSelected() && !config.getPassiveRememberMeRecord().contains(httpRequests.getHost())){
                requestsHeaders = Tools.setHeaders(requestsHeaders,"Cookie","rememberMe=0",0);
                // 加入到历史清单里，下次不再增加header
                config.getPassiveRememberMeRecord().add(httpRequests.getHost());
            }

            // 当用户勾选了强制刷新浏览器，不使用缓存时
            if(main2Tag.getFlushBrowserCheckBox().isSelected()){
                requestsHeaders = Tools.setHeaders(requestsHeaders,"Cache-Control","no-cache",1);
                requestsHeaders = Tools.deleteHeader(requestsHeaders,"If-Modified-Since");
                requestsHeaders = Tools.deleteHeader(requestsHeaders,"If-None-Match");
            }

            // 当用户勾选了修改User-Agent
            if(main2Tag.getUserAgentCheckBox().isSelected()){
                String user_agent_value = "";
                if(main2Tag.getChromeRadioButton().isSelected()){
                    user_agent_value = GlobalKeys.CHROME_UA;
                }
                else if(main2Tag.getFirefoxRadioButton().isSelected()){
                    user_agent_value = GlobalKeys.FIREFOX_UA;
                }
                else if(main2Tag.getIE7RadioButton().isSelected()){
                    user_agent_value = GlobalKeys.IE7_UA;
                }
                else if(main2Tag.getIphoneRadioButton().isSelected()){
                    user_agent_value = GlobalKeys.IPHONE_UA;
                }
                requestsHeaders = Tools.setHeaders(requestsHeaders,"User-Agent",user_agent_value,1);
            }

            // 自定义头部的功能开启逻辑
            if(main2Tag.getDirHeaderCheckBox().isSelected()){
                // 1. 获取面板里用户填写的内容
                String dirHeaderText = main2Tag.getDirHeaderTextArea().getText().trim();
                // 2. 解析内容
                HashMap<String,String> newHeader = Tools.changeStrToHeader(dirHeaderText);
                // 3. 替换请求报文里的内容
                for(Map.Entry<String,String> entry: newHeader.entrySet()){
                    String key = entry.getKey();
                    String value = entry.getValue();
                    // cookie走追加，其他走的是覆盖逻辑
                    if(key.equals("Cookie")){
                        requestsHeaders = Tools.setHeaders(requestsHeaders,key,value,0);
                    }
                    // 如果按了追加按钮，则追加，否则覆盖
                    if(main2Tag.getDirHeaderAddButton().isSelected()){
                        requestsHeaders = Tools.setHeaders(requestsHeaders,key,value,0);
                    }
                    else{
                        requestsHeaders = Tools.setHeaders(requestsHeaders,key,value,1);
                    }
                }
            }

            // 获取当前数据包的数据，追加内容，重组新的数据包
            byte[] byteBody = Tools.getBody(messageIsRequest,newRequests,this.helpers);
            // 将重组的数据包更新，并赋值到newRequests中
            newRequests = this.helpers.buildHttpMessage(requestsHeaders,byteBody);
            // 更新数据包
            messageInfo.setRequest(newRequests);
        }
        // 响应的才走下面的逻辑
        else {
            // 全局修改
            // 是否修改状态码302变200，结合全局配置
            if(main2Tag.getStatusTo200CheckBox().isSelected()){
                newResponse = Tools.changeStatus(newResponse);
            }
            // 是否自动美化response，会结合全局配置
            if(main2Tag.getResponseBeautyCheckBox().isSelected()){
                newResponse = new PrettyTagController().pretty(newResponse,false,this.helpers);
            }
            // 更新数据包
            messageInfo.setResponse(newResponse);
        }
    }

    /**
     * requestsResponseTab的扩展页面
     * @param controller
     * @param editable
     * @return
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
//        return new PrettyTag(this.callbacks);
        return new LinkTag(this.callbacks);
    }

    /**
     * 卸载插件触发
     */
    @Override
    public void extensionUnloaded() {
        config.setExtensionUnload(true);
        // 将数据库给关掉，可能会导致抛异常，因为卸载程序后，线程并未及时结束，线程的结果会做入库，所以会在这个时候导致异常 TODO：
        DBHelper.connectionClose(config.getDbHelper().getConn());
    }

    /**
     * bp模块，会单独起线程，不会阻塞代理的流量
     * 注意：需要在【Dashboard】->【Live audit from Proxy（all traffic）】-> 【Deduplication】里取消勾选按钮，不然重复流量就不会触发到该逻辑
     * @param messageInfo
     * @return
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse messageInfo) {
        // 主动和被动的分析的分析流程
        HTTPRequests httpRequests = new HTTPRequests(this.callbacks, messageInfo);
        HTTPResponse httpResponse = new HTTPResponse(this.callbacks, messageInfo);
        // 整个被动的流程都放这里
        new VulnsController().passiveScanController(httpRequests,httpResponse,messageInfo,tags,config);
        // 主动探测
        new VulnsController().activeScanController(httpRequests,httpResponse,tags,config);
        // 项目管理的逻辑
        projectManager(httpResponse,config,messageInfo,tags);

        return null;
    }

    /**
     * 是否要将数据放入到项目的队列中，进行访问
     * @param httpResponse
     * @param config
     * @param messageInfo
     * @param tags
     */
    public static void projectManager(HTTPResponse httpResponse,Config config,IHttpRequestResponse messageInfo,Tags tags){

        // 加一个前置的过滤判断，减少无效数据进入分析，占用系统资源；如果后缀是
        if(Tools.fileSuffixIsInBlackList(httpResponse.getFileSuffix())) return;

        // 获取【目标管理】里的根域名
        HashSet<String> targetHashSet = config.getTags().getProjectTableTag().getTargetHashSet();
        // 获取【项目管理】里面已经访问过的host地址
        Set<String> urlHashSet = config.getTags().getProjectTableTag().getUrlHashSet();

        // 0、先做一个判断，如果【目标管理】的hashset为空，就不往下走
        if(targetHashSet.size() == 0) return;

        // 1、先判断当前用户访问的页面，是否是根目录，以及是否是在【目标管理】里；如果是在，判断下当前表格有没有数据，如果也有，那就录入到表格里
        if(httpResponse.getCurrentPath().equals("/")){
            // 判断当前目标是否在项目管理里
            boolean isInDomain = false;
            for(String domain:targetHashSet){
                if (httpResponse.getHost().contains(domain)){
                    isInDomain = true;
                    break;
                }
            }

            // 如果在项目管理的目标里，并且不在urlHashSet里，那才要处理
            if(isInDomain && !urlHashSet.contains(httpResponse.getHost())){
                // 将它们更新到urlhashset里，并且录入到数据库、表格里
                urlHashSet.add(httpResponse.getHost());
                // 下面是准备做入库的逻辑
                // 判断是否为IP
                if(httpResponse.isIP(httpResponse.getDomain())){
                    // 如果是ip，表示getDomain也是IP，不用转化可以直接用了
                    httpResponse.setIp(httpResponse.getDomain());
                }
                else{
                    // 如果不是ip，说明是域名，要转化成IP
                    httpResponse.setIp(HTTPResponse.getIP(httpResponse.getDomain()));
                }

                // 这里的add函数做了修改，会自动入库
                tags.getProjectTableTag().add(
                        httpResponse,
                        messageInfo
                );
            }
        }

        // 2、对网站里的内容识别，提取出需要访问的url
        ProjectController.analysisNeedScanLinkAndAdd(urlHashSet,targetHashSet, config.getProjectManagerUrls(), httpResponse);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}

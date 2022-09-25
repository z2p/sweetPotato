package burp.Controller;

import burp.Bootstrap.*;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.Ui.DirScanTag;
import burp.Ui.Tags;

import java.net.URL;
import java.util.ArrayList;

/**
 * 用来存放 用户自己操作的功能逻辑
 * 例如：用户自己要对某个目标下发目录扫描
 */
public class DirScanThread implements Runnable{

    private ArrayList<String> urls;
    private Tags tags;
    private Config config;
    private String type;

    public DirScanThread(ArrayList<String> urls, Tags tags, Config config, String type){
        this.urls = urls;
        this.tags = tags;
        this.config = config;
        this.type = type;
    }

    @Override
    public void run() {
        IHttpRequestResponse messageInfo = null;
        DirScanTag dirScanTag = tags.getDirScanTag();

        for(int i=0;i<urls.size();i++){
            dirScanTag.getScanStatusLabel().setText("当前状态：进行中 " + (i+1) + "/" + urls.size());
            String url = urls.get(i);
            try{
                messageInfo = BurpSuiteRequests.get(url,null, config.getCallbacks(),false,config,5);
                System.out.println("正在对 " + url + " 进行访问...");
                // 解析成对象
                HTTPRequests newHTTPRequest = new HTTPRequests(config.getCallbacks(), messageInfo);
                HTTPResponse newHTTPResponse = new HTTPResponse(config.getCallbacks(),messageInfo);
                // 调用被动扫描做一次分析
                new VulnsController().passiveScanController(newHTTPRequest,newHTTPResponse,messageInfo,tags,config);
                // 添加到目录扫描的tag里
                dirScanTag.add(
                        Tools.URLDecoderString(newHTTPResponse.getUrl()), // url解码
                        newHTTPResponse.getTitle(),
                        newHTTPResponse.getServer(),
                        newHTTPResponse.getLanguage(),
                        newHTTPResponse.getLength(),
                        newHTTPResponse.getStatus(),
                        type,
                        messageInfo
                );
                // 给一份到项目管理
                BurpExtender.projectManager(newHTTPResponse,config,messageInfo,tags);

            } catch (Exception e){
                // 出现异常，在界面上也给予一定提示
                dirScanTag.add(
                        Tools.URLDecoderString(url),    // url解码
                        "Exception",
                        "Exception",
                        "Exception",
                        -1,
                        -1,
                        type,
                        messageInfo
                );
                e.printStackTrace();
            } finally {
                // 增加睡眠间隔
                try {
                    Thread.sleep(200);
                }catch (Exception e2){}
            }
        }
        dirScanTag.setScanStatusToDefault();
    }
}

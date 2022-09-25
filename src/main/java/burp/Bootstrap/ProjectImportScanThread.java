package burp.Bootstrap;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.Ui.Tags;


public class ProjectImportScanThread extends Thread {

    private Config config;
    private IBurpExtenderCallbacks callbacks;
    private Tags tags;

    public ProjectImportScanThread(Config config) {
        this.config = config;
        this.callbacks = config.getCallbacks();
        this.tags = config.getTags();
    }

    @Override
    public void run(){
        for(String url:config.getProjectImportTargetList()){
            // 对每个目标进行访问，拿到请求和响应包
            System.out.println("正在对 " + url + " 进行访问");
            IHttpRequestResponse messageInfo = BurpSuiteRequests.get(url,null,callbacks,true,config,5);
            // 如果出现异常，messageInfo就是null，那就跳过再进入循环
            if(messageInfo == null) continue;
            // 解析
            HTTPResponse httpResponse = new HTTPResponse(callbacks,messageInfo);
            // 给到项目管理的逻辑开始分析
            BurpExtender.projectManager(httpResponse,config,messageInfo,tags);
        }
        // 更新按钮，设置可操作
        config.getProjectOtherOptionMenu().getImportItem().setEnabled(true);
    }
}

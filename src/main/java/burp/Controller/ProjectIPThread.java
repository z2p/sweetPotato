package burp.Controller;

import burp.Bootstrap.Config;
import burp.Bootstrap.CustomBurpUrl;
import burp.Ui.ProjectTableTag;

import java.util.List;

public class ProjectIPThread extends Thread{

    private Config config;
    public ProjectIPThread(Config config) {
        this.config = config;
    }

    public void run(){

        while(true){
            // 0、如果用户未启动允许IP，那就休眠
            if(!config.getTags().getProjectTableTag().getIpCheckBox().isSelected()){
                try{
                    Thread.sleep(5000);
                    continue;
                } catch (Exception e){
                    e.printStackTrace();
                }
            }

            // 1、当插件被卸载，也关闭线程
            if (config.isExtensionUnload()) {
                break;
            }
            // 2、从表格里遍历，看一下是否有IP需要被访问的
            List<ProjectTableTag.TablesData> Udatas = config.getTags().getProjectTableTag().getUdatas();
            try{
                for(ProjectTableTag.TablesData tablesData:Udatas){
                    String ip = tablesData.getIp();
                    if(ip.contains("Exception")) continue;

                    String protocol = CustomBurpUrl.getRequestProtocol(tablesData.getUrl());
                    int port = CustomBurpUrl.getRequestPort(tablesData.getUrl());
                    String ipUrl = "";

                    if((port == 443 && protocol.equals("https")) || (port == 80 && protocol.equals("http"))){
                        ipUrl = protocol + "://" + ip;
                    }
                    else{
                        ipUrl = protocol + "://" + ip + ":" + port;
                    }

                    // 判断一下当前的IP是否已经在项目历史里了，如果已经在的IP，就不用进行访问
                    if(config.getProjectIPRecord().contains(ipUrl)) continue;
                    else{
                        // 添加到历史访问记录里
                        config.getProjectIPRecord().add(ipUrl);
                        // 加入到扫描任务池
                        config.getProjectManagerUrls().add(ipUrl);
                    }
                }
            } catch (Exception e){
                e.printStackTrace();
            }

            // 3、定期休眠，这个频率不宜太高
            try{
                Thread.sleep(5000);
            } catch (Exception e){
                e.printStackTrace();
            }
        }
    }
}

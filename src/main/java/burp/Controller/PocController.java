package burp.Controller;

import burp.Bootstrap.Config;
import burp.Poc.PocInfo;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;


public class PocController implements Runnable{

    private ArrayList<PocInfo> pocInfos;
    private Config config;

    public PocController(ArrayList<PocInfo> pocInfos,Config config){
        this.pocInfos = pocInfos;
        this.config = config;
    }

    @Override
    public void run() {
        for(int i=0;i< pocInfos.size();i++){

            config.getTags().getPocTag().getScanStatusLabel().setText("当前状态：进行中 " + (i+1) + "/" + pocInfos.size());
            try {
                PocInfo pocInfo = pocInfos.get(i);
                // 直接在配置文件里把包名都写上
                String className = "burp.Poc." + pocInfo.getPocName();
                // 获取poc的类
                Class pocClass = Class.forName(className);
                // 创建构造函数类的对象
                Constructor constructor = pocClass.getConstructor(PocInfo.class);
                Object pocObj = constructor.newInstance(pocInfo);
                // 获取方法
                Method pocCheck = pocClass.getDeclaredMethod("check");
                // 调用方法
                pocCheck.invoke(pocObj);

            } catch (Exception e) {
                e.printStackTrace();
            }

            try{
                Thread.sleep(500);
            } catch (Exception e){
                e.printStackTrace();
            }
        }
        config.getTags().getPocTag().setScanStatusToDefault();
    }
}

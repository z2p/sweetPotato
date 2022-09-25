package burp.Controller;

import burp.Bootstrap.Config;

public class BackGroundProjectCountThread extends Thread{

    private Config config;
    public BackGroundProjectCountThread(Config config) {
        this.config = config;
    }

    @Override
    public void run() {

        while(true) {
            // 1、获取一下当前的任务总数
            int size = config.getProjectManagerUrls().size();
            // 2、更新一下任务数量
            config.getTags().getProjectTableTag().getBackGroundProjectCount().setText("表格总数：" + config.getTags().getProjectTableTag().getUdatas().size() + "  后台任务：" + size + " ");
            // 3、定时清空一下 复制版的提示
            config.getTags().getProjectTableTag().getCopyTips().setText("");

            // 4、开始睡眠
            try {
                Thread.sleep(500);
                // add 对所有的set的大小进行一个打印，方便debug，后面可以注释掉
                {
                    //                System.out.println("===============");
//                System.out.println("FingerResult Set的大小："+config.getFingerResult().size());
//                System.out.println("RememberMe Set的大小：" + config.getPassiveRememberMeRecord().size());
//                System.out.println("VulnsResult Set的大小：" + config.getVulnsResult().size());
//                System.out.println("ActiveScanRecord Set的大小：" + config.getActiveScanRecord().size());
//                System.out.println("Target Set的大小：" + config.getTags().getProjectTableTag().getTargetHashSet().size());
//                System.out.println("Url Set的大小：" + config.getTags().getProjectTableTag().getUrlHashSet().size());
//                System.out.println("ProjectIPRecord的大小：" + config.getProjectIPRecord().size());
//                System.out.println("===============");
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
            // 4、当插件被卸载，也关闭线程
            if (config.isExtensionUnload()) {
                break;
            }
        }
    }
}

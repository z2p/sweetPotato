package burp.Ui;

import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.File;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import burp.Bootstrap.Config;
import burp.Bootstrap.Tools;
import burp.ITab;
import burp.IBurpExtenderCallbacks;


public class Tags implements ITab {

    private final JTabbedPane tabs;
    private String tagName;
    private FingerTag fingerTag;
    private VulnsTag vulnsTag;
    private Main2Tag main2Tag;
    private DirScanTag dirScanTag;
    private PocTag pocTag;
    private ProjectTableTag projectTableTag;
    private Config config;

    public Tags(IBurpExtenderCallbacks callbacks, String name, Config config) {

        this.tagName = name;
        this.config = config;
        // 将自己放到config中
        this.config.setTags(this);

        // 定义tab标签页
        tabs = new JTabbedPane();
        // 全局配置-窗口
        this.main2Tag = new Main2Tag(tabs,config);

        // 加载json配置文件
        // 指纹配置文件
        System.out.println("指纹配置文件地址：" + getMain2Tag().getFingerPathTextField().getText());
        this.config.setFingerJsonInfo(Tools.getJSONObject(getMain2Tag().getFingerPathTextField().getText()));
        // 敏感信息配置文件
        this.config.setInfoLeakJsonInfo(Tools.getJSONObject(getMain2Tag().getInfoPathTextField().getText()));
        // 漏洞配置文件
        this.config.setPocFingerJsonInfo(Tools.getJSONObject(getMain2Tag().getPocPathTextField().getText()));
        // 备份扫描配置文件
        this.config.setBackupFileJsonInfo(Tools.getJSONObject(getMain2Tag().getBackupPathTextField().getText()));
        // TODO 面板上要增加一个输入框
        this.config.setSensitivePathJsonInfo(Tools.getJSONObject(config.getJarPath() + "resources" + File.separator+ "sentitivePathFinger.json"));
        // TODO 语言文件的路径
        this.config.setLanguageFingerJsonInfo(Tools.getJSONObject(config.getJarPath() + "resources" + File.separator+ "languageFinger.json"));

        // 指纹-窗口
        this.fingerTag = new FingerTag(callbacks, tabs,this,config);
        // 脆弱性-窗口
        this.vulnsTag = new VulnsTag(callbacks,tabs,this.config);
        // 目录扫描-窗口
        this.dirScanTag = new DirScanTag(callbacks,tabs,this.config);
        // 漏洞利用-窗口 TODO：暂时不开放
        this.pocTag = new PocTag(tabs,config);
        // 项目管理-窗口
        this.projectTableTag = new ProjectTableTag(callbacks,tabs,this,config);

        // tab做监听器
        tabs.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {

                String selectTabsName = tabs.getTitleAt(tabs.getSelectedIndex());
                if(selectTabsName.equals("项目管理")){
                    // 设置项目管理，默认聚焦组件
                    JPanel optionPanel = projectTableTag.getOptionPanel();
                    optionPanel.dispatchEvent(new FocusEvent(optionPanel,FocusEvent.FOCUS_GAINED,true));
                    optionPanel.requestFocusInWindow();
                }
                // 修改选中的标签页名字颜色
                tabs.setForegroundAt(tabs.getSelectedIndex(),Color.BLACK);
            }
        });

        // 将整个tab加载到平台即可
        callbacks.customizeUiComponent(tabs);
        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(Tags.this);
    }

    public PocTag getPocTag() {
        return pocTag;
    }

    public ProjectTableTag getProjectTableTag() {
        return projectTableTag;
    }

    public void setMain2Tag(Main2Tag main2Tag) {
        this.main2Tag = main2Tag;
    }

    public FingerTag getFingerTag() {
        return fingerTag;
    }

    public VulnsTag getVulnsTag() {
        return vulnsTag;
    }

    public Main2Tag getMain2Tag(){ return this.main2Tag;}

    /**
     * 扫描队列tag
     * 可通过该类提供的方法,进行tag任务的添加与修改
     *
     * @return
     */
    public FingerTag getFingerTagClass() {
        return this.fingerTag;
    }

    public VulnsTag getVulnsTagClass(){
        return this.vulnsTag;
    }

    public DirScanTag getDirScanTag() {
        return dirScanTag;
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}
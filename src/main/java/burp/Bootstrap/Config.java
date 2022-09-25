package burp.Bootstrap;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.Ui.ProjectOtherOptionMenu;
import burp.Ui.TagPopMenu;
import burp.Ui.Tags;
import com.alibaba.fastjson.JSONObject;

import javax.swing.*;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

public class Config {

    public static String browserPath = "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe";
    public static final String macDefaultBrowserPath = "/Applications/Firefox.app/Contents/MacOS/firefox";
    public JSONObject fingerJsonInfo;   // 指纹具体信息
    public JSONObject infoLeakJsonInfo; // 敏感信息具体内容（相当于把json打开了）
    public JSONObject sensitivePathJsonInfo;    // 敏感目录信息
    public JSONObject languageFingerJsonInfo;   // 语言指纹具体信息
    public JSONObject backupFileJsonInfo;   // 备份文件的目录信息
    public JSONObject pocFingerJsonInfo;    // 漏洞信息文件
    public Set<String> fingerResult;      // 指纹历史数据存储
    public Set<String> vulnsResult;       // 脆弱性历史数据存储
    public Set<String> activeScanRecord;  // 主动扫描的目标存储
    public Set<String> passiveRememberMeRecord; // 被动增加rememberMe头部的历史目标存储
    private IExtensionHelpers helpers;   // helper
    private IBurpExtenderCallbacks callbacks;   // callbacks
    private Tags tags;  // tags
    private JTextArea consoleTextArea;  // 控制台的textarea，因为只会生成一个控制台，所以这个放在config里，给所有的对象进行调用
    private DBHelper dbHelper;  // dbhelper
    private boolean isExtensionUnload = false;
    private String jarPath = "";    // 保存当前插件的目录，绝对路径
    private Set<String> projectImportTargetList = Collections.synchronizedSet(new HashSet<>());  // 保存用户从页面导入目标的list
    private Vector<String> projectManagerUrls = new Vector<String>();
    private Set<String> projectIPRecord = Collections.synchronizedSet(new HashSet<>()); // 保存符合域名的所有IP
    private ProjectOtherOptionMenu projectOtherOptionMenu;

    public Set<String> getProjectIPRecord() {
        return projectIPRecord;
    }

    public ProjectOtherOptionMenu getProjectOtherOptionMenu() {
        return projectOtherOptionMenu;
    }

    public Config(){
        if(Tools.isMac()){
            browserPath = macDefaultBrowserPath;
        }
        this.fingerResult = Collections.synchronizedSet(new HashSet<>());;
        this.vulnsResult = Collections.synchronizedSet(new HashSet<>());;
        this.activeScanRecord = Collections.synchronizedSet(new HashSet<>());;
        this.passiveRememberMeRecord = Collections.synchronizedSet(new HashSet<>());;
        this.projectOtherOptionMenu = new ProjectOtherOptionMenu();
    }

    public Vector<String> getProjectManagerUrls() {
        return projectManagerUrls;
    }

    public Set<String> getProjectImportTargetList() {
        return projectImportTargetList;
    }

    public void setProjectImportTargetList(HashSet<String> projectImportTargetList) {
        this.projectImportTargetList = projectImportTargetList;
    }

    public String getJarPath() {
        return jarPath;
    }

    public void setJarPath(String jarPath) {
        this.jarPath = jarPath;
    }

    public void setExtensionUnload(boolean extensionUnload) {
        isExtensionUnload = extensionUnload;
    }

    public boolean isExtensionUnload() {
        return isExtensionUnload;
    }

    public JSONObject getBackupFileJsonInfo() {
        return backupFileJsonInfo;
    }

    public void setBackupFileJsonInfo(JSONObject backupFileJsonInfo) {
        this.backupFileJsonInfo = backupFileJsonInfo;
    }

    public JSONObject getPocFingerJsonInfo() {
        return pocFingerJsonInfo;
    }

    public void setDbHelper(DBHelper dbHelper) {
        this.dbHelper = dbHelper;
    }

    public DBHelper getDbHelper() {
        return dbHelper;
    }

    public void setPocFingerJsonInfo(JSONObject pocFingerJsonInfo) {
        this.pocFingerJsonInfo = pocFingerJsonInfo;
    }

    public Tags getTags() {
        return tags;
    }

    public void setTags(Tags tags) {
        this.tags = tags;
    }

    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    public void setHelpers(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public void setCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public Set getFingerResult() {
        return fingerResult;
    }

    public void setFingerResult(Set fingerResult) {
        this.fingerResult = fingerResult;
    }

    public JSONObject getLanguageFingerJsonInfo() {
        return languageFingerJsonInfo;
    }

    public void setLanguageFingerJsonInfo(JSONObject languageFingerJsonInfo) {
        this.languageFingerJsonInfo = languageFingerJsonInfo;
    }

    public Set getVulnsResult() {
        return vulnsResult;
    }

    public Set getActiveScanRecord() {
        return activeScanRecord;
    }

    public Set<String> getPassiveRememberMeRecord() {
        return passiveRememberMeRecord;
    }

    public JSONObject getSensitivePathJsonInfo() {
        return sensitivePathJsonInfo;
    }

    public void setSensitivePathJsonInfo(JSONObject sensitivePathJsonInfo) {
        this.sensitivePathJsonInfo = sensitivePathJsonInfo;
    }

    public JSONObject getFingerJsonInfo() {
        return fingerJsonInfo;
    }

    public void setFingerJsonInfo(JSONObject fingerJsonInfo) {
        this.fingerJsonInfo = fingerJsonInfo;
    }

    public JSONObject getInfoLeakJsonInfo() {
        return infoLeakJsonInfo;
    }

    public void setInfoLeakJsonInfo(JSONObject infoLeakJsonInfo) {
        this.infoLeakJsonInfo = infoLeakJsonInfo;
    }

    public static String getBrowserPath() {
        return browserPath;
    }

    public static String getMacDefaultBrowserPath() {
        return macDefaultBrowserPath;
    }

    public static void setBrowserPath(String browserPath) {
        Config.browserPath = browserPath;
    }
}

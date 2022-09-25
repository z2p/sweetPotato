package burp.Poc;

import burp.Bootstrap.Config;
import burp.IBurpExtenderCallbacks;
import burp.Ui.Tags;

public class PocInfo {

    private String target;
    private String pocName;
    private String level;
    private Tags tags;
    private Config config;
    private IBurpExtenderCallbacks callbacks;
    private String appName;
    private String showUserPocName;

    public PocInfo(String target, String pocName, String level, Tags tags, Config config,String appName,String showUserPocName){
        this.target = target;
        this.pocName = pocName;
        this.level = level;
        this.tags = tags;
        this.config = config;
        this.callbacks = config.getCallbacks();
        this.appName = appName;
        this.showUserPocName = showUserPocName;
    }

    public String getAppName() {
        return appName;
    }

    public String getShowUserPocName() {
        return showUserPocName;
    }

    public String getTarget() {
        return target;
    }

    public String getPocName() {
        return pocName;
    }

    public String getLevel() {
        return level;
    }

    public Tags getTags() {
        return tags;
    }

    public Config getConfig() {
        return config;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
}

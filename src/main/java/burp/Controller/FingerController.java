package burp.Controller;
import burp.Bootstrap.Config;
import burp.Bootstrap.HTTPResponse;
import burp.Bootstrap.Tools;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.Ui.Tags;
import com.alibaba.fastjson.JSONObject;
import java.util.ArrayList;
import java.util.HashSet;

public class FingerController {

    ArrayList<String> fingers;

    public FingerController(Config config,HTTPResponse httpResponse){

        JSONObject jsonInfo = config.getFingerJsonInfo();
        fingers = Tools.fingerMatch(httpResponse.getHeaders(),httpResponse.getStrBody(),jsonInfo,httpResponse.getIconHash());
        httpResponse.setFingers(fingers);
    }

    public ArrayList<String> getFingers() {
        return fingers;
    }
}

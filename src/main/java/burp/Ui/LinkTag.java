package burp.Ui;

import burp.Bootstrap.HTTPResponse;
import burp.Bootstrap.Tools;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.ITextEditor;

import java.awt.*;
import java.util.HashSet;

/**
 * 在bp上response中增加一个tab页面，可以查看当前页面存在哪些link
 */
public class LinkTag implements IMessageEditorTab {

    private ITextEditor iTextEditor;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public LinkTag(IBurpExtenderCallbacks callbacks) {
        this.iTextEditor = callbacks.createTextEditor();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public String getTabCaption() {
        return "Links";
    }

    @Override
    public Component getUiComponent() {
        return iTextEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {

        if(!isRequest){
            // 如果是异常，或者就没内容，那就置为空
            if(new String(content).equals("link exception") || content.length == 0){
                iTextEditor.setText(new byte[]{});
                return;
            }

            HTTPResponse httpResponse = new HTTPResponse(content);
            httpResponse.analysisHeaders(helpers.analyzeResponse(content).getHeaders());

            String strContent = new String(content);
            String html = HTTPResponse.htmlDecodeFormat(strContent);
            String returnStr = "";
            HashSet<String> allLinks = HTTPResponse.getAllLinks(html, httpResponse.getHeaders(),new String(content),httpResponse.getHost());

            for(String str:allLinks){
                // 对数据进行一个url解码，需要验证一下
                str = Tools.URLDecoderString(str);
                returnStr += str + "\n";
            }
            // 换行去掉
            returnStr = returnStr.substring(0,returnStr.length()-1);
            iTextEditor.setText(returnStr.getBytes());
        }
    }

    @Override
    public byte[] getMessage() {
        return new byte[0];
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return new byte[0];
    }
}

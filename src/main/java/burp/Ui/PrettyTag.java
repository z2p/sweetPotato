package burp.Ui;

import burp.*;
import burp.Bootstrap.JsonFormat;
import burp.Controller.PrettyTagController;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

public class PrettyTag implements IMessageEditorTab{

    private ITextEditor iTextEditor;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PrettyTag(IBurpExtenderCallbacks callbacks){
        this.iTextEditor = callbacks.createTextEditor();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }
    @Override
    public String getTabCaption() {
        return "PrettyTab";
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

        iTextEditor.setText(new PrettyTagController().pretty(content,isRequest,this.helpers));
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

package burp.Ui;
import java.awt.*;
import java.awt.event.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;

import burp.*;
import burp.Bootstrap.Config;
import burp.Bootstrap.HTTPResponse;
import burp.Bootstrap.Tools;
import burp.Bootstrap.URLTableClass;
import burp.Controller.VulnsController;

import javax.swing.JButton;


public class FingerTag extends TagClass implements IMessageEditorController {

    public List<TablesData> Udatas = new ArrayList<TablesData>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IBurpExtenderCallbacks callbacks;
    private JTabbedPane requestTab;
    private JTabbedPane responseTab;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private Tags tags;
    private Main2Tag main2Tag;
    private JTabbedPane tabs;
    private URLTable urlTable;
    private Config config;

    public FingerTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs,Tags tags,Config config) {

        this.callbacks = callbacks;
        this.tags = tags;
        this.main2Tag = tags.getMain2Tag();
        this.config = config;
        this.tabs = tabs;
        // 总面板
        JPanel mainPanel = new JPanel(new BorderLayout());
        // 主面板的内容设置间隔
        mainPanel.setBorder(new EmptyBorder(5,5,5,5));
        // 添加上方的按钮
        mainPanel.add(getButtonPanel(),BorderLayout.NORTH);
        // 添加中间和下方的表格
        mainPanel.add(getTableAndRaw(),BorderLayout.CENTER);
        // 将自己加到tabs中
        tabs.addTab("指纹", mainPanel);
    }

    /**
     * 中间的表格以及下方的请求和响应报文
     * @return
     */
    public JSplitPane getTableAndRaw(){
        JSplitPane tableAndRaw = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        urlTable = new URLTable(FingerTag.this,config);
        // 特殊字段的长宽限制
        urlTable.getColumn("language").setMaxWidth(90);
        urlTable.getColumn("language").setMinWidth(90);
        // urltable增加右键监听器
        urlTable.tagPopMenuAddListener();

        // 将表格放到scrollpane中
        JScrollPane tableScrollPane = new JScrollPane(urlTable);
        // 请求和响应的
        JSplitPane rawPane = new JSplitPane();
        rawPane.setResizeWeight(0.5);

        // 请求的面板
        this.requestTab = new JTabbedPane();
        this.requestTextEditor = this.callbacks.createMessageEditor(FingerTag.this, false);
        this.requestTab.addTab("Request", this.requestTextEditor.getComponent());

        // 响应的面板
        this.responseTab = new JTabbedPane();
        this.responseTextEditor = this.callbacks.createMessageEditor(FingerTag.this, false);
        this.responseTab.addTab("Response", this.responseTextEditor.getComponent());

        rawPane.add(this.requestTab,"left");
        rawPane.add(this.responseTab,"right");
        tableAndRaw.add(tableScrollPane,"left");
        tableAndRaw.add(rawPane,"right");
        return tableAndRaw;
    }

    /**
     * 最上方的按钮和查询栏
     * @return
     */
    public JPanel getButtonPanel(){
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.LEFT,5,5));

        JLabel searchLabel = new JLabel("检索：");
        JButton buttonSearch = new JButton("搜索");
        JButton buttonClean = new JButton("清空数据");
        JButton buttonFromHistory = new JButton("分析History");
        JLabel analysisHistoryTips = new JLabel();

        JTextField textFieldSearch = new JTextField("");
        textFieldSearch.setColumns(30);

        buttonPanel.add(searchLabel);
        buttonPanel.add(textFieldSearch);
        buttonPanel.add(buttonSearch);
        buttonPanel.add(buttonClean);
        buttonPanel.add(buttonFromHistory);
        buttonPanel.add(analysisHistoryTips);

        buttonClean.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cleanTable();
                // 同时要清空一下hashset
                config.getFingerResult().clear();
                // 主动发包的也要清除，因为有主动发包探测指纹
                config.getActiveScanRecord().clear();
            }
        });

        buttonFromHistory.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] messageInfos = callbacks.getProxyHistory();
                int i=1;

                // 调用分析
                for(IHttpRequestResponse messageInfo:messageInfos){
                    analysisHistoryTips.setText("正在分析History：" + i + "/" + messageInfos.length);
                    HTTPResponse httpResponse = new HTTPResponse(callbacks, messageInfo);
                    // 调用指纹识别和编程语言识别
                    new VulnsController().fingerAndLanguage(config,httpResponse,messageInfo);
                    i +=1;
                }
                analysisHistoryTips.setText("");
            }
        });

        return buttonPanel;
    }

    @Override
    public void cleanTable(){
        while(Udatas.size()>0){
            Udatas.remove(0);
            fireTableDataChanged();
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return super.isCellEditable(rowIndex, columnIndex);
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 10;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "url";
            case 2:
                return "host";
            case 3:
                return "title";
            case 4:
                return "finger";
            case 5:
                return "server";
            case 6:
                return "language";
            case 7:
                return "length";
            case 8:
                return "status";
            case 9:
                return "time";

        }
        return null;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.id;
            case 1:
                return datas.url;
            case 2:
                return datas.host;
            case 3:
                return datas.title;
            case 4:
                return datas.finger;
            case 5:
                return datas.server;
            case 6:
                return datas.language;
            case 7:
                return datas.status;
            case 8:
                return datas.length;
            case 9:
                return datas.time;
        }
        return null;
    }

    public int add(String url, String host, String title,String server,int length,
                   int status, String finger,String language, IHttpRequestResponse messageInfo) {
        // 使finger的标签变色
        if(this.tabs.getSelectedIndex()!=1){
            this.tabs.setForegroundAt(1,new Color(255,102,51));
        }

        synchronized (this.Udatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String time = sdf.format(d);
            int id = this.Udatas.size()+1;
            this.Udatas.add(
                    new TablesData(id,url,host,title,server,length,status,finger,language,time,messageInfo)
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }

    /**
     * 自定义Table
     */
    public class URLTable extends URLTableClass {

        public URLTable(TableModel tableModel,Config config) {
            super(tableModel,config);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = Udatas.get(convertRowIndexToModel(row));
            requestTextEditor.setMessage(dataEntry.messageInfo.getRequest(), true);
            int messageLength = 50000;
            if(dataEntry.messageInfo.getResponse().length >= messageLength){
                byte[] finalMessage = Tools.cutByte(dataEntry.messageInfo.getResponse(),messageLength);
                responseTextEditor.setMessage(finalMessage,true);
            } else{
                responseTextEditor.setMessage(dataEntry.messageInfo.getResponse(), false);
            }
            currentlyDisplayedItem = dataEntry.messageInfo;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     * 界面显示数据存储模块
     */
    private class TablesData {
        final int id;
        final String url;
        final String host;
        final String title;
        final String server;
        final int length;
        final int status;
        final String finger;
        final String time;
        final String language;
        final IHttpRequestResponse messageInfo;

        public TablesData(int id, String url, String host,
                          String title, String server,int status, int length,
                          String finger, String language,String time, IHttpRequestResponse messageInfo) {
            this.id = id;
            this.url = url;
            this.host = host;
            this.title = title;
            this.server = server;
            this.status = status;
            this.length = length;
            this.finger = finger;
            this.language = language;
            this.time = time;
            this.messageInfo = messageInfo;
        }
    }
}


package burp.Ui;

import burp.Bootstrap.Config;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.Tools;
import burp.*;
import burp.Bootstrap.URLTableClass;
import burp.Controller.DirScanThread;
import com.alibaba.fastjson.JSONArray;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class DirScanTag extends TagClass implements IMessageEditorController {

    private List<TablesData> Udatas = new ArrayList<TablesData>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IBurpExtenderCallbacks callbacks;
    private JTabbedPane requestTab;
    private JTabbedPane responseTab;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private Main2Tag main2Tag;
    private JTabbedPane tabs;
    private URLTable urlTable;
    private Config config;
    private JLabel scanStatusLabel;
    private JTextField scanTargetTextField;
    private JComboBox scanTypeComboBox;


    public DirScanTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, Config config) {

        this.callbacks = callbacks;
        this.config = config;
        this.main2Tag = config.getTags().getMain2Tag();;
        this.tabs = tabs;
        // 总面板
        JPanel mainPanel = new JPanel(new BorderLayout());
        // 主面板的内容设置间隔
        mainPanel.setBorder(new EmptyBorder(5,5,5,5));

        mainPanel.add(getButtonPanel(),BorderLayout.NORTH);
        // 添加中间和下方的表格
        mainPanel.add(getTableAndRaw(),BorderLayout.CENTER);
        tabs.addTab("目录扫描", mainPanel);
    }

    public JPanel getButtonPanel(){
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.LEFT,5,5));
        JLabel scanTargetLabel = new JLabel("下发扫描：");
        JButton buttonScan = new JButton("开始扫描");
        JButton buttonClean = new JButton("清空数据");
        scanTargetTextField = new JTextField("");
        scanTargetTextField.setColumns(30);

        String[] scanTypes = {
                "正常访问","备份文件扫描"
        };
        scanTypeComboBox = new JComboBox(scanTypes);
        scanStatusLabel = new JLabel("当前状态：未开始扫描");

        buttonPanel.add(scanTargetLabel);
        buttonPanel.add(scanTargetTextField);
        buttonPanel.add(scanTypeComboBox);
        buttonPanel.add(buttonScan);
        buttonPanel.add(buttonClean);
        buttonPanel.add(scanStatusLabel);

        // 清除按钮的监听器
        buttonClean.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cleanTable();
            }
        });

        // 按下扫描按钮的监听器
        buttonScan.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                doScan();
            }
        });

        // 按下回车执行扫描的监听器
        scanTargetTextField.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {

            }

            @Override
            public void keyPressed(KeyEvent e) {
                // 按下回车
                if(e.getKeyCode() == 10){
                    doScan();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {

            }
        });

        return buttonPanel;
    }

    public void doScan(){
        String userInput = scanTargetTextField.getText();
        // 将用户的输入组装成urls
        ArrayList<String> targets = Tools.getUrls(userInput);
        // 由于是本地发包，当输入的目标数量过多的时候，让用户做一下判断
        if(targets.size() >= 50){
            int choise = JOptionPane.showOptionDialog(null,"当前选中的文件目标url过多（>=50），请选择下发的操作","下发任务选择框",JOptionPane.DEFAULT_OPTION,JOptionPane.QUESTION_MESSAGE,null,new String[]{"全部下发","下发50个","下发20个","取消扫描"},"下发20个");

            // 取消扫描
            if(choise == 3){
                targets.clear();
            }
            // 下发20个
            else if(choise == 2){
                while(targets.size() >20){
                    targets.remove(0);
                }
            }
            // 下发50个
            else if(choise == 1){
                while(targets.size() > 50){
                    targets.remove(0);
                }
            }
            // 全部下发
            else if(choise == 0){}
        }
        // 定义扫描对象
        DirScanThread dirScanThread;
        // 获取用户选择的类型
        String scanType = scanTypeComboBox.getSelectedItem().toString();
        if(scanType.contains("备份文件扫描")){
            JSONArray paths = config.getBackupFileJsonInfo().getJSONArray("package");
            ArrayList<String> backupTargets = new ArrayList<String>();
            for(int i=0;i<paths.size();i++){
                String path = paths.getString(i);
                for(int j=0;j<targets.size();j++){
                    String url = targets.get(j);
                    if(path.contains("%domain%")){
                        path = path.replace("%domain%",CustomBurpUrl.getDomain(url));
                    }
                    backupTargets.add(url+path);
                }
            }
            dirScanThread = new DirScanThread(backupTargets,config.getTags(),config,scanType);
        }
        else if(scanType.contains("正常访问")){
            dirScanThread = new DirScanThread(targets,config.getTags(),config,scanType);
        }
        else{
            return;
        }

        Thread t = new Thread(dirScanThread);
        t.start();
    }

    public void setScanStatusToDefault(){
        scanStatusLabel.setText("当前状态：未开始扫描");
    }

    public JLabel getScanStatusLabel() {
        return scanStatusLabel;
    }

    /**
     * 中间的表格以及下方的请求和响应报文
     * @return
     */
    public JSplitPane getTableAndRaw(){
        JSplitPane tableAndRaw = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        urlTable = new URLTable(DirScanTag.this,config);
        urlTable.tagPopMenuAddListener();
        // 特殊字段的长宽限制
        urlTable.getColumn("type").setMinWidth(150);
        urlTable.getColumn("type").setMaxWidth(150);
        urlTable.getColumn("server").setMaxWidth(200);
        urlTable.getColumn("server").setMinWidth(200);
        urlTable.getColumn("language").setMaxWidth(90);
        urlTable.getColumn("language").setMinWidth(90);

        // 将表格放到scrollpane中
        JScrollPane tableScrollPane = new JScrollPane(urlTable);

        // 请求和响应的
        JSplitPane rawPane = new JSplitPane();
        rawPane.setResizeWeight(0.5);

        // 请求的面板
        this.requestTab = new JTabbedPane();
        this.requestTextEditor = this.callbacks.createMessageEditor(DirScanTag.this, false);
        this.requestTab.addTab("Request", this.requestTextEditor.getComponent());

        // 响应的面板
        this.responseTab = new JTabbedPane();
        this.responseTextEditor = this.callbacks.createMessageEditor(DirScanTag.this, false);
        this.responseTab.addTab("Response", this.responseTextEditor.getComponent());

        rawPane.add(this.requestTab,"left");
        rawPane.add(this.responseTab,"right");
        tableAndRaw.add(tableScrollPane,"left");
        tableAndRaw.add(rawPane,"right");
        return tableAndRaw;
    }

    public URLTable getUrlTable() {
        return urlTable;
    }

    public void setUrlTable(URLTable urlTable) {
        this.urlTable = urlTable;
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
        return 9;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "url";
            case 2:
                return "title";
            case 3:
                return "server";
            case 4:
                return "language";
            case 5:
                return "length";
            case 6:
                return "status";
            case 7:
                return "type";
            case 8:
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
                return datas.title;
            case 3:
                return datas.server;
            case 4:
                return datas.language;
            case 5:
                return datas.length;
            case 6:
                return datas.status;
            case 7:
                return datas.type;
            case 8:
                return datas.time;
        }
        return null;
    }

    @Override
    public void cleanTable() {
        while(Udatas.size()>0){
            Udatas.remove(0);
            fireTableDataChanged();
        }
        requestTextEditor.setMessage(new byte[]{},true);
        responseTextEditor.setMessage(new byte[]{},false);
    }

    public int add(String url, String title,String server,String language,int length,
                   int status, String type, IHttpRequestResponse messageInfo) {
        // 使finger的标签变色
        if(this.tabs.getSelectedIndex()!=3){
            this.tabs.setForegroundAt(3,new Color(255,102,51));
        }

        synchronized (this.Udatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String time = sdf.format(d);
            int id = this.Udatas.size()+1;
            this.Udatas.add(
                    new TablesData(id,url,title,server,language,length,status,type,time,messageInfo)
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
            if(dataEntry.messageInfo.getRequest() != null){
                requestTextEditor.setMessage(dataEntry.messageInfo.getRequest(), true);
            }
            else{
                requestTextEditor.setMessage(new byte[]{},true);
            }

            if(dataEntry.messageInfo.getResponse() != null){
                responseTextEditor.setMessage(dataEntry.messageInfo.getResponse(), false);
            }
            else{
                responseTextEditor.setMessage(new byte[]{}, false);
            }
            currentlyDisplayedItem = dataEntry.messageInfo;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     * 界面显示数据存储模块
     */
    private static class TablesData {
        final int id;
        final String url;
        final String title;
        final String server;
        final String language;
        final int length;
        final int status;
        final String time;
        final String type;
        final IHttpRequestResponse messageInfo;

        public TablesData(int id, String url,
                          String title, String server,String language,int length,int status,
                          String type,String time, IHttpRequestResponse messageInfo) {
            this.id = id;
            this.url = url;
            this.title = title;
            this.server = server;
            this.language = language;
            this.status = status;
            this.length = length;
            this.type = type;
            this.time = time;
            this.messageInfo = messageInfo;
        }
    }
}


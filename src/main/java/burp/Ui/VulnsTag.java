package burp.Ui;

import burp.*;
import burp.Bootstrap.Tools;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import burp.Bootstrap.Config;
import burp.Bootstrap.URLTableClass;


public class VulnsTag extends TagClass implements IMessageEditorController {

    private List<TablesData> Udatas = new ArrayList<TablesData>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private Main2Tag main2Tag;
    private JTabbedPane requestTab;
    private JTabbedPane responseTab;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private IBurpExtenderCallbacks callbacks;
    private URLTable urlTable;
    private JTabbedPane tabs;
    private Config config;
    private Tags tags;

    public VulnsTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs,Config config){

        this.callbacks = callbacks;
        this.config = config;
        this.tags = config.getTags();
        this.main2Tag = tags.getMain2Tag();
        this.tabs = tabs;
        // 总面板
        JPanel mainPanel = new JPanel(new BorderLayout());
        // 主面板的内容设置间隔
        mainPanel.setBorder(new EmptyBorder(5,5,5,5));

        // 添加上方的表格
        mainPanel.add(getButtonPanel(),BorderLayout.NORTH);
        // 添加中间和下方的表格
        mainPanel.add(getTableAndRaw(),BorderLayout.CENTER);
        tabs.addTab("脆弱性",mainPanel);
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
        buttonClean.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                delete();
            }
        });

        JTextField textFieldSearch = new JTextField("");
        textFieldSearch.setColumns(30);

        JLabel splitLabel1 = new JLabel("|");
        JLabel splitLabel2 = new JLabel("|");
        splitLabel1.setEnabled(false);
        splitLabel2.setEnabled(false);

        JLabel vulnInfo = new JLabel("漏洞筛选：");
        JRadioButton allLevelButton = new JRadioButton("全部",true);
        JRadioButton highLevelButton = new JRadioButton("高");
        JRadioButton normalLevelButton = new JRadioButton("中");
        JRadioButton lowLevelButton = new JRadioButton("低");
        ButtonGroup levelGroup = new ButtonGroup();

        JLabel passiveOrActiveInfo = new JLabel("发现方式：");
        JRadioButton allScanTypeButton = new JRadioButton("全部",true);
        JRadioButton passiveButton = new JRadioButton("被动");
        JRadioButton activeButton = new JRadioButton("主动");
        ButtonGroup scanTypeGroup = new ButtonGroup();

        levelGroup.add(allLevelButton);
        levelGroup.add(highLevelButton);
        levelGroup.add(normalLevelButton);
        levelGroup.add(lowLevelButton);

        scanTypeGroup.add(allScanTypeButton);
        scanTypeGroup.add(passiveButton);
        scanTypeGroup.add(activeButton);

        buttonPanel.add(searchLabel);
        buttonPanel.add(textFieldSearch);
        buttonPanel.add(buttonSearch);
        buttonPanel.add(buttonClean);
        buttonPanel.add(splitLabel1);

        buttonPanel.add(vulnInfo);
        buttonPanel.add(allLevelButton);
        buttonPanel.add(highLevelButton);
        buttonPanel.add(normalLevelButton);
        buttonPanel.add(lowLevelButton);
        buttonPanel.add(splitLabel2);

        buttonPanel.add(passiveOrActiveInfo);
        buttonPanel.add(allScanTypeButton);
        buttonPanel.add(passiveButton);
        buttonPanel.add(activeButton);

        return buttonPanel;
    }

    /**
     * 中间和下方的表格
     * @return
     */
    public JSplitPane getTableAndRaw(){
        JSplitPane tableAndRaw = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        urlTable = new URLTable(VulnsTag.this);
        urlTable.tagPopMenuAddListener();
        // 特殊字段设置居中
        DefaultTableCellRenderer render = new DefaultTableCellRenderer() {
            public Component getTableCellRendererComponent(JTable table, Object value,boolean isSelected, boolean hasFocus, int row, int column) {
                Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if(table.getColumnName(column).equals("vulns")) {
                    cell.setForeground(new Color(9,109,217));
                }
                else{
                    cell.setForeground(new Color(0,0,0));
                }
                return cell;
            }
        };
        render.setHorizontalAlignment(SwingConstants.CENTER);
        urlTable.getColumn("#").setCellRenderer(render);
        urlTable.getColumn("url").setCellRenderer(render);
        urlTable.getColumn("title").setCellRenderer(render);
        urlTable.getColumn("vulns").setCellRenderer(render);
        urlTable.getColumn("level").setCellRenderer(render);
        urlTable.getColumn("server").setCellRenderer(render);
        urlTable.getColumn("language").setCellRenderer(render);
        urlTable.getColumn("length").setCellRenderer(render);
        urlTable.getColumn("status").setCellRenderer(render);
        urlTable.getColumn("time").setCellRenderer(render);
        // 特殊字段的长度限制
        urlTable.getColumn("url").setPreferredWidth(250);
        urlTable.getColumn("vulns").setPreferredWidth(300);
        urlTable.getColumn("server").setMinWidth(80);
        urlTable.getColumn("level").setMaxWidth(60);
        urlTable.getColumn("level").setMinWidth(60);
        urlTable.getColumn("language").setMaxWidth(90);
        urlTable.getColumn("language").setMinWidth(90);
        // 将表格放到scrollpane中
        JScrollPane tableScrollPane = new JScrollPane(urlTable);

        // 请求和响应
        JSplitPane rawPane = new JSplitPane();
        rawPane.setResizeWeight(0.5);

        // 请求面板
        this.requestTab = new JTabbedPane();
        this.requestTextEditor = this.callbacks.createMessageEditor(VulnsTag.this,false);
        this.requestTab.addTab("Request",this.requestTextEditor.getComponent());

        // 响应面板
        this.responseTab = new JTabbedPane();
        this.responseTextEditor = this.callbacks.createMessageEditor(VulnsTag.this,false);
        this.responseTab.addTab("Response",this.responseTextEditor.getComponent());

        rawPane.add(this.requestTab,"left");
        rawPane.add(this.responseTab,"right");
        tableAndRaw.add(tableScrollPane,"left");
        tableAndRaw.add(rawPane,"right");
        return tableAndRaw;
    }

    /**
     * 界面显示数据存储模块
     */
    private static class TablesData {
        final int id;
        final String url;
        final String title;
        final String server;
        final String level;
        final int length;
        final int status;
        final String vulns;
        final String time;
        final String language;
        final IHttpRequestResponse messageInfo;

        public TablesData(int id, String url,
                          String title, String vulns,String server,String language,String level,int status, int length,
                          String time, IHttpRequestResponse messageInfo) {
            this.id = id;
            this.url = url;
            this.title = title;
            this.vulns = vulns;

            this.server = server;
            this.level = level;
            this.status = status;
            this.length = length;
            this.language = language;
            this.time = time;
            this.messageInfo = messageInfo;
        }
    }

    /**
     * 自定义Table
     */
    private class URLTable extends URLTableClass {
        public URLTable(TableModel tableModel) {
            super(tableModel,config);
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = VulnsTag.this.Udatas.get(convertRowIndexToModel(row));
            requestTextEditor.setMessage(dataEntry.messageInfo.getRequest(), true);
            responseTextEditor.setMessage(dataEntry.messageInfo.getResponse(), false);
            currentlyDisplayedItem = dataEntry.messageInfo;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    public void delete(){
        while(Udatas.size()>0){
            Udatas.remove(0);
            fireTableDataChanged();
        }
        // 同时要清空一下hashset
        config.getVulnsResult().clear();
        // 主动发包的也要清除，因为有主动发包探测指纹
        config.getActiveScanRecord().clear();
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
    public String getColumnName(int columnIndex){
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "url";
            case 2:
                return "title";
            case 3:
                return "vulns";
            case 4:
                return "server";
            case 5:
                return "language";
            case 6:
                return "level";
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
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
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
                return datas.vulns;
            case 4:
                return datas.server;
            case 5:
                return datas.language;
            case 6:
                return datas.level;
            case 7:
                return datas.status;
            case 8:
                return datas.length;
            case 9:
                return datas.time;
        }
        return null;
    }

    @Override
    public void cleanTable() {

    }

    public int add(String url, String title,String vulns,String server,String language,String level,int length,
                   int status,  IHttpRequestResponse messageInfo) {

        int index = (int)this.tags.getTabsName().get("脆弱性");
        if(this.tabs.getSelectedIndex()!=index){
            this.tabs.setForegroundAt(index,new Color(255,102,51));
        }

        synchronized (this.Udatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String time = sdf.format(d);
            int id = this.Udatas.size()+1;
            this.Udatas.add(
                    new VulnsTag.TablesData(id,url,title,vulns,server,language,level,length,status,time,messageInfo)
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }
}
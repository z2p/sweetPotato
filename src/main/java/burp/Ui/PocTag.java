package burp.Ui;

import burp.*;
import burp.Bootstrap.Config;
import burp.Bootstrap.URLTableClass;
import burp.Controller.PocController;
import burp.Poc.PocInfo;
import com.alibaba.fastjson.JSONObject;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.*;
import java.lang.reflect.Array;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import burp.Bootstrap.Tools;

public class PocTag extends TagClass implements IMessageEditorController {

    private Config config;
    private IHttpRequestResponse currentlyDisplayedItem;
    private JTabbedPane tabs;
    private JPanel mainPanel;
    private JPanel northPanel;
    private JTextField targetTextField;
    private JButton startButton;
    private JLabel targetLabel;
    private JTree pocTree;
    private JScrollPane pocTreePanel;
    private JTable scanTable;
    private JTabbedPane southPane;
    private JSplitPane contentPanel;
    private JSplitPane tableAndInfoPanel;
    private JPanel configPanel;
    private JSplitPane requestAndResponsePanel;
    private URLTable urlTable;
    private JScrollPane scanTablePanel;
    private List<TablesData> Udatas = new ArrayList<TablesData>();
    private JTextField usernameTextField;
    private JTextField passwordTextField;
    private JTextField usernamesFilePathTextField;
    private JTextField passwordsFilePathTextField;
    private JPanel singleUserPanel;
    private JPanel unSignleUserPanel;
    private JTextField cookieTextField;
    private JComboBox useMethodCheckBox;
    private JLabel usernamesLabel;
    private JLabel passwordsLabel;
    private JLabel usernameLabel;
    private JLabel passwordLabel;
    private JPanel cookiePanel;
    private JLabel cookieLabel;
    private JPanel useMethodPanel;
    private JLabel useMethodLabel;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private JTabbedPane requestTab;
    private JTabbedPane responseTab;
    private IBurpExtenderCallbacks callbacks;
    private JButton expandButton;
    private JPanel pocPanel;
    private JPanel pocTreeButtonPanel;
    private JSplitPane configAndDetailPane;
    private JPanel detailPanel;
    private JPanel vulTitlePanel;
    private JTextField vulTitleTips;
    private JTextArea detailMessageArea;
    private JScrollPane detailMessagePanel;
    private String selectPocName = "";
    private String selectPocLevel = "";
    private String selectAppName = "";
    private String showUserPocName = "";
    private String selectPocPackageName = "";
    private String pocDetailMessage = "";
    private JButton cleanButton;
    private JLabel scanStatusLabel;

    private JSONObject pocInfo;

    public PocTag(JTabbedPane tabs,Config config){
        this.config = config;
        this.callbacks = config.getCallbacks();
        this.tabs = tabs;
        this.urlTable = new URLTable(PocTag.this);
        this.pocInfo = config.getPocFingerJsonInfo();
        // 如果配置文件为null，不显示界面和加载配置
        if(pocInfo == null) return;

        $$$setupUI$$$();
        // 我的初始化
        myInit();

        // 添加到全局tag
        tabs.addTab("漏洞利用",mainPanel);
    }

    public void myInit(){

        // url输入框默认不允许输入
        targetTextField.setEditable(false);
        targetTextField.setEnabled(false);
        startButton.setEnabled(false);
        // 输入框增加监听器
        targetTextField.addKeyListener(new KeyListener() {
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
        // 清空按钮监听器
        cleanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cleanTable();
            }
        });

        // table init
        {
            urlTable.getColumn("server").setMinWidth(200);
            urlTable.getColumn("server").setMaxWidth(200);
            urlTable.setDisableRigthMouseAction(true);
        }
        // 配置参数默认全部不展示
        setAllParaVisible(false);

        // 请求和响应
        {
            this.requestTab = new JTabbedPane();
            this.responseTab = new JTabbedPane();
            this.requestTextEditor = this.callbacks.createMessageEditor(PocTag.this,false);
            this.responseTextEditor = this.callbacks.createMessageEditor(PocTag.this,false);
            this.requestTab.add("Request",this.requestTextEditor.getComponent());
            this.responseTab.add("Response",this.responseTextEditor.getComponent());

            this.requestAndResponsePanel.add(this.requestTab,"left");
            this.requestAndResponsePanel.add(this.responseTab,"right");
            this.requestAndResponsePanel.setResizeWeight(0.5);
        }

        // 下方的漏洞参数和漏洞描述
        {
            this.configAndDetailPane.setResizeWeight(0.5);
            this.configAndDetailPane.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    configAndDetailPane.setDividerLocation(0.5);
                }

                @Override
                public void componentMoved(ComponentEvent e) {
                    super.componentMoved(e);
                }

                @Override
                public void componentShown(ComponentEvent e) {
                    super.componentShown(e);
                }

                @Override
                public void componentHidden(ComponentEvent e) {
                    super.componentHidden(e);
                }
            });
        }

        // 树状结构
        {
//            contentPanel.setDividerLocation(350);
            contentPanel.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    super.componentResized(e);
                    contentPanel.setDividerLocation(0.20);
                }

                @Override
                public void componentMoved(ComponentEvent e) {
                    super.componentMoved(e);
                }

                @Override
                public void componentShown(ComponentEvent e) {
                    super.componentShown(e);
                }

                @Override
                public void componentHidden(ComponentEvent e) {
                    super.componentHidden(e);
                }
            });

            ArrayList<String> appNames = new ArrayList<String>();
            DefaultMutableTreeNode root = new DefaultMutableTreeNode("Web漏洞");

            for(Map.Entry<String,Object> entry: pocInfo.entrySet()){
                String appName = entry.getKey();
                appNames.add(appName);
            }

            // 对app名称进行排序，因为entryset会导致乱序
            Collections.sort(appNames);
            // 生成具体的树状结构内容，根据组件名
            for(int i=0;i<appNames.size();i++){
                String appName = appNames.get(i);
                DefaultMutableTreeNode appNameRoot = new DefaultMutableTreeNode(appName);

                for(Map.Entry<String,Object> entry2: pocInfo.getJSONObject(appName).getJSONObject("Pocs").entrySet()){
                    String pocName = entry2.getKey();
                    DefaultMutableTreeNode pocNameNode = new DefaultMutableTreeNode(pocName);
                    appNameRoot.add(pocNameNode);
                }
                appNameRoot.setUserObject(appName + " (" + appNameRoot.getChildCount() + ")");
                root.add(appNameRoot);
            }
            root.setUserObject(root.getUserObject() + " (" + root.getChildCount() + ")");
            pocTree = new JTree(root);
            pocTreePanel.setViewportView(pocTree);

            // 树增加监听器
            pocTree.addTreeSelectionListener(new TreeSelectionListener() {
                @Override
                // 当用户做树状的切换时
                public void valueChanged(TreeSelectionEvent e) {
                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) pocTree.getLastSelectedPathComponent();
                    // 如果节点不存在，或者不是最深的节点
                    if(node == null || node.getDepth() != 0){
                        // 设置输入框可输入内容
                        targetTextField.setEditable(false);
                        targetTextField.setEnabled(false);
                        startButton.setEnabled(false);
                        detailMessageArea.setText("");
                        return;
                    }
                    // 如果选择了节点
                    if(node.isLeaf()){
                        // 设置输入框可输入内容
                        targetTextField.setEditable(true);
                        targetTextField.setEnabled(true);
                        startButton.setEnabled(true);
                        // 修改对应的参数界面可视化的情况
                        changeTreeAndParaPanel(node);
                    }
                    System.out.println("当前位置：" + node.toString() + " 深度为：" + node.getDepth());
                }
            });
        }

        // 检测按钮，被按下
        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                doScan();
            }
        });
        // 树状展开和折叠的功能
        expandButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(expandButton.getText().equals("全部展开")){
                    expandTree(pocTree,true);
                    expandButton.setText("全部折叠");
                }
                else if(expandButton.getText().equals("全部折叠")){
                    expandTree(pocTree,false);
                    expandButton.setText("全部展开");
                }
            }
        });
        this.contentPanel.setOneTouchExpandable(true);
        this.contentPanel.setResizeWeight(0.25);

    }

    public void doScan(){
        String userInput = targetTextField.getText();
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
        // 组装pocinfo对象
        ArrayList<PocInfo> pocInfos = new ArrayList<PocInfo>();
        for(String target:targets){
            PocInfo pocInfo = new PocInfo(target,selectPocName,selectPocLevel, config.getTags(), config,selectAppName,showUserPocName);
            pocInfos.add(pocInfo);
        }
        // 获取当前的信息，并进行线程调用
        PocController pc = new PocController(pocInfos,config);
        Thread t = new Thread(pc);
        t.start();
        System.out.println("漏洞检测已经启动");
    }

    public void setAllParaVisible(boolean isvisible){
        usernamesLabel.setVisible(isvisible);
        usernamesFilePathTextField.setVisible(isvisible);
        passwordsLabel.setVisible(isvisible);
        passwordsFilePathTextField.setVisible(isvisible);
        usernameLabel.setVisible(isvisible);
        usernameTextField.setVisible(isvisible);
        passwordLabel.setVisible(isvisible);
        passwordTextField.setVisible(isvisible);
        cookieLabel.setVisible(isvisible);
        cookieTextField.setVisible(isvisible);
        useMethodLabel.setVisible(isvisible);
        useMethodCheckBox.setVisible(isvisible);
    }

    public void cleanAllPara(){
        usernamesFilePathTextField.setText("");
        passwordsFilePathTextField.setText("");
        usernameTextField.setText("");
        passwordTextField.setText("");
        cookieTextField.setText("");
    }

    /**
     * 当改变树节点选择时，参数panel如何变化
     */
    public void changeTreeAndParaPanel(DefaultMutableTreeNode node){
        // 先拿配置文件
        JSONObject pocInfo = config.getPocFingerJsonInfo();
        // 拿组件名称
        String appName = node.getParent().toString().split("\\(")[0].trim();
        // 拿漏洞名称
        String pocName = node.toString();
        // 根据组件名称，查看该漏洞的信息，渲染界面
        JSONObject eachPocInfo = pocInfo.getJSONObject(appName).getJSONObject("Pocs").getJSONObject(pocName);
        // 从json里获取信息，看这个漏洞需不需要渲染界面
        boolean isRequired = (boolean) eachPocInfo.get("is_required");
        // 如果需要，就要开始渲染了
        if(isRequired){
            // 要结合配置文件里的参数，评估需要开放哪些内容
            setAllParaVisible(true);
        }
        else{
            // 将所有界面设置为不可见
            setAllParaVisible(false);
        }
        // 清空之前参数界面输入的内容
        cleanAllPara();

        // 设置当前被选中的poc名称
        selectPocName = eachPocInfo.getString("pocName");
        selectAppName = node.getParent().toString();
        showUserPocName = node.toString();
        // 获取漏洞描述细节
        pocDetailMessage = eachPocInfo.getString("pocDetailMessage");
        detailMessageArea.setText(pocDetailMessage);

        // 切换到参数配置的panel，不展示请求和响应
        this.southPane.setSelectedIndex(0);

        // 拿下父节点的名称
        System.out.println("appName: " + node.getParent().toString() + " pocName: " + node.toString() + " poc路径名: " + selectPocName);
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
                return datas.pocName;
            case 4:
                return datas.title;
            case 5:
                return datas.server;
            case 6:
                return datas.length;
            case 7:
                return datas.status;
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

    public int add(String url, String host, String pocName,String title,String server,int length,int status, IHttpRequestResponse messageInfo) {
        synchronized (this.Udatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String time = sdf.format(d);
            int id = this.Udatas.size()+1;
            this.Udatas.add(
                    new TablesData(id,url,host,pocName,title,server,length,status,time,messageInfo)
            );
            fireTableRowsInserted(id, id);
            return id;
        }
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
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "url";
            case 2:
                return "host";
            case 3:
                return "pocName";
            case 4:
                return "title";
            case 5:
                return "server";
            case 6:
                return "length";
            case 7:
                return "status";
            case 8:
                return "time";
        }
        return null;
    }

    /**
     * 自定义Table
     */
    public class URLTable extends URLTableClass {

        public int focusedRowIndex = -1;

        public URLTable(TableModel tableModel) {
            super(tableModel,config);
        }

        public int getFocusedRowIndex() {
            return focusedRowIndex;
        }

        public void setFocusedRowIndex(int focusedRowIndex) {
            this.focusedRowIndex = focusedRowIndex;
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
            // 使请求和响应的panel先展示
            southPane.setSelectedIndex(1);
        }
    }

    public static void expandTree(JTree tree,boolean expand) {
        TreeNode root = (TreeNode) tree.getModel().getRoot();
        expandAll(tree, new TreePath(root), expand);
    }

    /**
     * 展开树状
     * @param tree
     * @param parent
     * @param expand
     */
    private static void expandAll(JTree tree, TreePath parent, boolean expand) {
        // Traverse children
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() >= 0) {

            for (Enumeration e = node.children(); e.hasMoreElements(); ) {
                TreeNode n = (TreeNode) e.nextElement();
                TreePath path = parent.pathByAddingChild(n);
                expandAll(tree, path, expand);
            }
        }

        // Expansion or collapse must be done bottom-up
        if (expand) {
            tree.expandPath(parent);
        } else {
            tree.collapsePath(parent);

        }
    }

    private void $$$setupUI$$$() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout(0, 0));
        northPanel = new JPanel();
        northPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        mainPanel.add(northPanel, BorderLayout.NORTH);
        northPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        targetLabel = new JLabel();
        targetLabel.setText("请输入目标：");
        northPanel.add(targetLabel);
        targetTextField = new JTextField();
        targetTextField.setName("");
        targetTextField.setPreferredSize(new Dimension(300, 25));
        targetTextField.setText("");
        targetTextField.setToolTipText("");
        northPanel.add(targetTextField);
        startButton = new JButton();
        startButton.setText("开始检测");
        northPanel.add(startButton);
        cleanButton = new JButton();
        cleanButton.setText("清空数据");
        northPanel.add(cleanButton);
        scanStatusLabel = new JLabel();
        scanStatusLabel.setText("当前状态：未开始扫描");
        northPanel.add(scanStatusLabel);
        contentPanel = new JSplitPane();
        contentPanel.setOrientation(1);
        contentPanel.setResizeWeight(0.5);
        mainPanel.add(contentPanel, BorderLayout.CENTER);
        tableAndInfoPanel = new JSplitPane();
        tableAndInfoPanel.setOrientation(0);
        contentPanel.setRightComponent(tableAndInfoPanel);
        tableAndInfoPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        southPane = new JTabbedPane();
        tableAndInfoPanel.setRightComponent(southPane);
        configAndDetailPane = new JSplitPane();
        southPane.addTab("参数配置", configAndDetailPane);
        configPanel = new JPanel();
        configPanel.setLayout(new GridLayoutManager(5, 1, new Insets(0, 0, 0, 0), -1, -1));
        configAndDetailPane.setLeftComponent(configPanel);
        configPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        unSignleUserPanel = new JPanel();
        unSignleUserPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        configPanel.add(unSignleUserPanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        usernamesLabel = new JLabel();
        usernamesLabel.setText("用户名字典:");
        unSignleUserPanel.add(usernamesLabel);
        usernamesFilePathTextField = new JTextField();
        usernamesFilePathTextField.setPreferredSize(new Dimension(150, 25));
        unSignleUserPanel.add(usernamesFilePathTextField);
        passwordsLabel = new JLabel();
        passwordsLabel.setText("密码字典:");
        unSignleUserPanel.add(passwordsLabel);
        passwordsFilePathTextField = new JTextField();
        passwordsFilePathTextField.setPreferredSize(new Dimension(150, 25));
        unSignleUserPanel.add(passwordsFilePathTextField);
        final Spacer spacer1 = new Spacer();
        configPanel.add(spacer1, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        singleUserPanel = new JPanel();
        singleUserPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        configPanel.add(singleUserPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        usernameLabel = new JLabel();
        usernameLabel.setText("用户名:");
        singleUserPanel.add(usernameLabel);
        usernameTextField = new JTextField();
        usernameTextField.setPreferredSize(new Dimension(120, 25));
        singleUserPanel.add(usernameTextField);
        passwordLabel = new JLabel();
        passwordLabel.setText("密码:");
        singleUserPanel.add(passwordLabel);
        passwordTextField = new JTextField();
        passwordTextField.setPreferredSize(new Dimension(120, 25));
        singleUserPanel.add(passwordTextField);
        cookiePanel = new JPanel();
        cookiePanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        configPanel.add(cookiePanel, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        cookieLabel = new JLabel();
        cookieLabel.setText("Cookie:");
        cookiePanel.add(cookieLabel);
        cookieTextField = new JTextField();
        cookieTextField.setPreferredSize(new Dimension(200, 25));
        cookiePanel.add(cookieTextField);
        useMethodPanel = new JPanel();
        useMethodPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        configPanel.add(useMethodPanel, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        useMethodLabel = new JLabel();
        useMethodLabel.setText("利用方式:");
        useMethodPanel.add(useMethodLabel);
        useMethodCheckBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        useMethodCheckBox.setModel(defaultComboBoxModel1);
        useMethodCheckBox.setPreferredSize(new Dimension(120, 25));
        useMethodPanel.add(useMethodCheckBox);
        detailPanel = new JPanel();
        detailPanel.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        configAndDetailPane.setRightComponent(detailPanel);
        detailPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        vulTitlePanel = new JPanel();
        vulTitlePanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        detailPanel.add(vulTitlePanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        vulTitleTips = new JTextField();
        vulTitleTips.setBackground(new Color(-855310));
        vulTitleTips.setEditable(false);
        vulTitleTips.setHorizontalAlignment(2);
        vulTitleTips.setPreferredSize(new Dimension(70, 25));
        vulTitleTips.setText("漏洞信息");
        vulTitlePanel.add(vulTitleTips);
        detailMessagePanel = new JScrollPane();
        detailPanel.add(detailMessagePanel, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        detailMessageArea = new JTextArea();
        detailMessageArea.setBackground(new Color(-263173));
        detailMessageArea.setEditable(false);
        detailMessageArea.setLineWrap(true);
        detailMessageArea.putClientProperty("html.disable", Boolean.TRUE);
        detailMessagePanel.setViewportView(detailMessageArea);
        requestAndResponsePanel = new JSplitPane();
        southPane.addTab("请求和响应", requestAndResponsePanel);
        scanTablePanel = new JScrollPane();
        tableAndInfoPanel.setLeftComponent(scanTablePanel);
//        scanTable = new JTable();
        scanTablePanel.setViewportView(urlTable);
        pocPanel = new JPanel();
        pocPanel.setLayout(new BorderLayout(0, 0));
        contentPanel.setLeftComponent(pocPanel);
        pocTreePanel = new JScrollPane();
        pocPanel.add(pocTreePanel, BorderLayout.CENTER);
        pocTreePanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        pocTree = new JTree();
        pocTree.setDropMode(DropMode.ON);
        pocTree.setRowHeight(30);
        pocTree.putClientProperty("JTree.lineStyle", "");
        pocTreePanel.setViewportView(pocTree);
        pocTreeButtonPanel = new JPanel();
        pocTreeButtonPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        pocPanel.add(pocTreeButtonPanel, BorderLayout.NORTH);
        pocTreeButtonPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        expandButton = new JButton();
        expandButton.setText("全部展开");
        pocTreeButtonPanel.add(expandButton);
        final Spacer spacer2 = new Spacer();
        pocTreeButtonPanel.add(spacer2);
    }

    public void setScanStatusToDefault(){
        scanStatusLabel.setText("当前状态：未开始扫描");
    }

    public JLabel getScanStatusLabel() {
        return scanStatusLabel;
    }

    /**
     * 界面显示数据存储模块
     */
    private static class TablesData {
        final int id;
        final String url;
        final String host;
        final String pocName;
        final String title;
        final String server;
        final int length;
        final int status;
        final String time;
        final IHttpRequestResponse messageInfo;

        public TablesData(int id, String url, String host,String pocName,
                          String title, String server,int length,int status,
                          String time, IHttpRequestResponse messageInfo) {
            this.id = id;
            this.url = url;
            this.host = host;
            this.pocName = pocName;
            this.title = title;
            this.server = server;
            this.length = length;
            this.status = status;
            this.time = time;
            this.messageInfo = messageInfo;
        }
    }
}

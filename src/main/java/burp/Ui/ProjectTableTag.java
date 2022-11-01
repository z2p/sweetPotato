package burp.Ui;

import burp.*;
import burp.Bootstrap.*;
import com.intellij.uiDesigner.core.Spacer;
import jxl.Workbook;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;


public class ProjectTableTag implements IMessageEditorController {

    private JPanel mainPanel;
    private JPanel optionPanel;
    private JButton choiceProjectButton;
    private JLabel status;
    private JSplitPane tableAndRawPane;
    private JTable targetTable;
    private JSplitPane requestsAndResponsePanel;
    private JScrollPane targetTableScrollPanel;
    private JCheckBox recursionCheckBox;
    private JLabel copyTips;
    private JTextField searchField;
    private JButton searchButton;
    private JLabel backGroundProjectCount;
    private JCheckBox ipCheckBox;
    private JButton otherOptionButton;

    private TableRowSorter<AbstractTableModel> sorter;

    public List<TablesData> Udatas = new ArrayList<TablesData>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IBurpExtenderCallbacks callbacks;
    private JTabbedPane requestTab;
    private JTabbedPane responseTab;
    private JTabbedPane tabs;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private Tags tags;
    private Main2Tag main2Tag;
    private Config config;
    private ProjectOpenList projectOpenList;
    private JFileChooser projectFileChooser;
    private File userChoiceFile;    // 用户打开的文件
    private HashSet<String> targetHashSet = new HashSet<String>();  // 用来存放【目标管理】里的目标根域名
    private Set<String> urlHashSet = Collections.synchronizedSet(new HashSet<>());     // 用来存放表格里的关键字，关键字为url根目录，如 http://www.baidu.com:8080/
    private DBHelper dbHelper;
    private MyTableModel myTableModel;
    private QuickFofa quickFofa;

    // 用来存放各个键的顺序，方便后面查找和使用
    ArrayList<String> tableSortList = new ArrayList<String>();
    // combo box
    private JComboBox isCheckComboBox = new JComboBox();
    private JComboBox assetTypeComboBox = new JComboBox();
    int count = 0;

    public File getUserChoiceFile() {
        return userChoiceFile;
    }

    public JCheckBox getIpCheckBox() {
        return ipCheckBox;
    }

    public ProjectTableTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, Tags tags, Config config) {

        this.callbacks = callbacks;
        this.tags = tags;
        this.main2Tag = tags.getMain2Tag();
        this.config = config;
        this.tabs = tabs;
        this.myTableModel = new MyTableModel(this.Udatas);
        targetTable = new URLTable(this.myTableModel);
        // 初始化布局
        $$$setupUI$$$();
        // 自定义的布局
        init();
        // 将自己添加到tabs中
        tabs.addTab("项目管理", mainPanel);
    }

    public void init() {

        // otherOption的监听器
        otherOptionButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {
                otherOptionButtonClickAction(e);
            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {

            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        // 初始化文件选择
        projectFileChooser = new JFileChooser(Tools.getExtensionFilePath(callbacks) + "/result/");

        // 设置在未选择项目时，大部分按钮不可用
        buttonEnableChange(false);

        // 目标设置管理的UI界面
        projectOpenList = new ProjectOpenList(targetHashSet, config);

        // 快速fofa的UI界面 TODO:quickfofa
        quickFofa = new QuickFofa(config);

        // 请求面板
        this.requestTab = new JTabbedPane();
        this.requestTextEditor = this.callbacks.createMessageEditor(this, false);
        this.requestTab.add("Request", this.requestTextEditor.getComponent());

        // 响应面板
        this.responseTab = new JTabbedPane();
        this.responseTextEditor = this.callbacks.createMessageEditor(this, false);
        this.responseTab.add("Response", this.responseTextEditor.getComponent());

        requestsAndResponsePanel.add(requestTab, "left");
        requestsAndResponsePanel.add(responseTab, "right");
        // 请求和响应的初始比例
        requestsAndResponsePanel.setResizeWeight(0.5);
        tableAndRawPane.setResizeWeight(0.55);
        tableAndRawPane.setOneTouchExpandable(true);
        tableAndRawPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                super.componentResized(e);
            }
        });
        // table处理
        {
            // 按顺序存放一下各个字段
            this.tableSortList.add("id");
            this.tableSortList.add("url");
            this.tableSortList.add("domain");
            this.tableSortList.add("status");
            this.tableSortList.add("length");
            this.tableSortList.add("title");
            this.tableSortList.add("server");
            this.tableSortList.add("finger");
            this.tableSortList.add("isCheck");
            this.tableSortList.add("assetType");
            this.tableSortList.add("comments");
            this.tableSortList.add("ip");
            this.tableSortList.add("updateTime");

            // table美化
            DefaultTableCellRenderer render = new DefaultTableCellRenderer() {
                public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                    Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                    // TODO: 这里后面要改一下
                    if ((table.getColumnName(column).equals("finger") || table.getColumnName(column).equals("title")) && !table.getValueAt(row, column).toString().equals("Exception")) {
                        cell.setForeground(new Color(9, 109, 217));
                    } else if (table.getValueAt(row, column).toString().equals("Exception")) {
                        cell.setForeground(new Color(252, 25, 68));
                    } else {
                        cell.setForeground(new Color(0, 0, 0));
                    }

                    if (isSelected) {
                        cell.setBackground(new Color(255, 197, 153));
                    } else {
                        if (row % 2 == 0) {
                            cell.setBackground(new Color(255, 255, 255));
                        } else {
                            cell.setBackground(new Color(242, 242, 242));
                        }
                    }
                    return cell;
                }
            };
            render.setHorizontalAlignment(SwingConstants.CENTER);
            int columnCount = this.myTableModel.getColumnCount();
            for (int i = 0; i < columnCount; i++) {
                targetTable.getColumn(this.myTableModel.getColumnName(i)).setCellRenderer(render);
            }
            targetTable.getColumn("#").setMinWidth(50);
            targetTable.getColumn("#").setMaxWidth(50);
            targetTable.getColumn("status").setMinWidth(65);
            targetTable.getColumn("status").setMaxWidth(65);
            targetTable.getColumn("length").setMinWidth(65);
            targetTable.getColumn("length").setMaxWidth(65);
            targetTable.getColumn("updateTime").setMinWidth(140);
            targetTable.getColumn("updateTime").setMaxWidth(140);
            targetTable.getColumn("url").setMinWidth(200);
            targetTable.getColumn("url").setPreferredWidth(200);
            targetTable.getColumn("domain").setPreferredWidth(150);
            targetTable.getColumn("title").setMinWidth(300);
            targetTable.getColumn("ip").setMinWidth(110);
            targetTable.getColumn("ip").setMaxWidth(110);
            targetTable.getColumn("isCheck").setMinWidth(70);
            targetTable.getColumn("isCheck").setMaxWidth(70);
            targetTable.getColumn("assetType").setMinWidth(80);
            targetTable.getColumn("assetType").setMaxWidth(80);

            targetTable.setAutoCreateRowSorter(true);
            sorter = new TableRowSorter(this.myTableModel);
            targetTable.setRowSorter(sorter);
        }

        searchField.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {

            }

            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == 10) {
                    searchButtonAction();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {
                searchButtonAction();
            }
        });

        searchButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                searchButtonAction();
            }
        });

        // 当用户点击【目标管理】的操作
        config.getProjectOtherOptionMenu().getSetTargetItem().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                projectOpenList.setVisible(true);
            }
        });

        // 当用户点击【快速fofa】的操作 TODO: 快速fofa
        config.getProjectOtherOptionMenu().getQuickFofaItem().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                quickFofa.setVisible(true);
            }
        });

        // 当用户点击【其他操作】
        optionPanel.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {
            }

            @Override
            public void keyPressed(KeyEvent e) {
                // 10 = 回车
                if (e.getKeyCode() == 10) {
                    clickChoiceProjectAction();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {

            }
        });

        // 当用户点击【选择项目】的操作
        choiceProjectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clickChoiceProjectAction();
            }
        });

        // 当用户点击【导入】的操作
        config.getProjectOtherOptionMenu().getImportItem().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                importButtonAction();
            }
        });

        // 当用户点击【导出】的操作
        config.getProjectOtherOptionMenu().getExportItem().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportButtonAction();
            }
        });

        // TODO：当用户点击【刷新标题】的操作
        config.getProjectOtherOptionMenu().getFreshTitleItem().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                freshTitleAction();
            }
        });

        // 当用户点击【全局搜索】的操作
        config.getProjectOtherOptionMenu().getGlobalSearchItem().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                globalSearchItemClickAction();
            }
        });

        // 当用户点击【批量复制】的操作
        config.getProjectOtherOptionMenu().getCopySelectItem().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectUrl();
            }
        });
    }

    public void copySelectUrl(){

        String resultUrl = "";
        int[] selectRows = targetTable.getSelectedRows();
        for (int i=0;i<selectRows.length;i++){
            int j = selectRows[i];
            String url = targetTable.getValueAt(j,1).toString();
            resultUrl += url + "\n";
        }
        // 添加到剪切板
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        // 封装文本内容
        Transferable transferable = new StringSelection(resultUrl);
        // 文件放到剪切板
        clipboard.setContents(transferable,null);
        // 更新tips
        copyTips.setText("复制成功：" + selectRows.length + "条");
    }

    /**
     * 当用户点击了全局搜索
     */
    public void globalSearchItemClickAction(){
        String userInput = JOptionPane.showInputDialog("请输入需要搜索的内容（注：会从所有的Response里检索，会有一定的卡顿，输入的关键词必须大于等于3个字符，中文可能会有一定问题）");
        if (userInput.length() < 3) return;
        String searchResult = "检索结果：\t\t\t\n";
        try{
            for(TablesData tablesData:Udatas){
                String responseStr = Tools.byteToString(tablesData.getMessageInfo().getResponse(),null);
                if (responseStr.contains(userInput)){
                    searchResult += "第" + tablesData.getId() + "行：存在关键词：" + userInput + "\n";
                }
            }
        } catch (Exception e){
            System.out.println("全局搜索出现了异常");
        }
        JOptionPane.showMessageDialog(null,searchResult);
    }

    /**
     * 点击otherOptionButton触发的事件
     */
    public void otherOptionButtonClickAction(MouseEvent e) {

        config.getProjectOtherOptionMenu().getMenu().show(otherOptionButton, e.getX(), e.getY());
    }

    /**
     * 导出按钮触发的事件
     */
    public void exportButtonAction() {

        // 1、弹出选择框，让用户选择另存为的地址
        JFileChooser fileChooser = new JFileChooser(Tools.getExtensionFilePath(callbacks) + "/result/");
        FileNameExtensionFilter fileNameExtensionFilter = new FileNameExtensionFilter(".xls", "xls");
        fileChooser.addChoosableFileFilter(fileNameExtensionFilter);
        fileChooser.setFileFilter(fileNameExtensionFilter);

        int action = fileChooser.showSaveDialog(null);
        if (action != JFileChooser.APPROVE_OPTION) return;
        File f = fileChooser.getSelectedFile();
        if (f == null) return;

        // 2、判断一下当前的文件是否存在，如果存在是否要让用户选择是否覆盖
        if (f.exists()) {
            int choise = JOptionPane.showOptionDialog(null, "当前文件已存在，是否要覆盖？", "文件已存在", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{"取消", "覆盖"}, "覆盖");

            if (choise == 0) return;
            if (choise == 1) {
                f.deleteOnExit();
                try {
                    f.createNewFile();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        // 3、将jtable的内容写入到excel里
        String[] tableHeaders = new String[]{
                "id", "url", "domain", "status", "length", "title", "server", "finger", "isCheck", "assetType", "comments", "ip", "updateTime"
        };
        WritableWorkbook workbook = null;
        try {
            workbook = Workbook.createWorkbook(f);
            WritableSheet sheet = workbook.createSheet("export", 0);
            // 写表头
            for (int i = 0; i < tableHeaders.length; i++) {
                jxl.write.Label l = new jxl.write.Label(i, 0, tableHeaders[i]);
                sheet.addCell(l);
            }
            // 写内容
            for (TablesData tablesData : Udatas) {
                String[] tableValues = new String[]{
                        String.valueOf(tablesData.id),
                        tablesData.url,
                        tablesData.domain,
                        String.valueOf(tablesData.status),
                        String.valueOf(tablesData.length),
                        tablesData.title,
                        tablesData.server,
                        tablesData.finger,
                        tablesData.isCheck,
                        tablesData.assetType,
                        tablesData.comments,
                        tablesData.ip,
                        tablesData.updateTime
                };
                for (int i = 0; i < tableHeaders.length; i++) {
                    jxl.write.Label l = new jxl.write.Label(i, tablesData.id + 1, tableValues[i]);
                    sheet.addCell(l);
                }
            }

            workbook.write();
            JOptionPane.showConfirmDialog(null, "保存成功，路径：" + f.getAbsolutePath(), "文件保存成功！", JOptionPane.DEFAULT_OPTION);
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showConfirmDialog(null, e.getMessage(), "文件保存异常！", JOptionPane.DEFAULT_OPTION);
        } finally {
            try {
                workbook.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    /**
     * 导入按钮触发的事件
     */
    public void importButtonAction() {

        // 1、弹出选择框，用户进行导入文件选择
        JFileChooser fileChooser = new JFileChooser(Tools.getExtensionFilePath(callbacks) + "/result/");
        FileNameExtensionFilter fileNameExtensionFilter = new FileNameExtensionFilter(".txt", "txt");
        fileChooser.addChoosableFileFilter(fileNameExtensionFilter);
        fileChooser.setFileFilter(fileNameExtensionFilter);

        int action = fileChooser.showOpenDialog(null);
        if (action != JFileChooser.APPROVE_OPTION) return;
        File f = fileChooser.getSelectedFile();
        if (f == null) return;
        // 2、读取文件里的内容
        try {
            // 获取到所有的目标
            String[] lines = Tools.readFile(f, false).split("\n");
            // 要对目标进行校验，看是否合法，然后添加到Vector里，给多个线程去消费
            for (String line : lines) {
                // TODO: 判断输入的是否是一个合法的地址
                // 将输入的内容进行了一定的http标准化，但未判断合法性
                String target = Tools.hostPortToUrl(line.trim());
                if (target.length() == 0) continue;
                // 定义一个全局的vector，并将url输入进去
                config.getProjectImportTargetList().add(target);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 3、读取完，写入到vector之后，要做什么？弹出对话框，让用户进行选择了，是要怎么扫
        int choise = JOptionPane.showOptionDialog(null, "请选择下发的操作，会对导入文件里的url进行访问（若非http[s]://前缀的会自动添加）\n注：只有域名符合才会加入到表格中展示", "下发任务选择框", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{"取消下发", "只下发域名符合的目标", "全部下发"}, "全部下发");

        // 取消下发
        if (choise == 0) {
            config.getProjectImportTargetList().clear();
            return;
        }
        // 只下发域名符合的目标
        else if (choise == 1) {
            HashSet<String> tempTargetList = new HashSet<String>();
            // 遍历targetHashSet
            for (String projectListEachTarget : targetHashSet) {
                // 遍历vector
                for (String target : config.getProjectImportTargetList()) {
                    if (target.contains(projectListEachTarget)) tempTargetList.add(projectListEachTarget);
                }
            }
            config.setProjectImportTargetList(tempTargetList);
        }
        // 全部下发，不需要处理，
        else if (choise == 2) {
        }
        // 4、判断hashset其中是否存在数据，如果有，那就可以起一个线程开始跑了
        if (config.getProjectImportTargetList().size() == 0) return;
        // 5、过程中，将导入的功能进行禁用，等线程结束后，才恢复按钮
        config.getProjectOtherOptionMenu().getImportItem().setEnabled(false);
        // 6、for循环
        ProjectImportScanThread projectImportScanThread = new ProjectImportScanThread(config);
        projectImportScanThread.start();
    }


    /**
     * 刷新标题按钮触发的事件
     */
    public void freshTitleAction() {
        // 1、先将表格中，异常的数据提出出来
        List<TablesData> exceptionDatas = new ArrayList<TablesData>();
        for (TablesData tablesData : Udatas) {
            if (tablesData.server.contains("Exception")) {
                exceptionDatas.add(tablesData);
            }
        }
        // 2、定义一个list，未来用于存储要扫描的目标信息
        List<TablesData> scanDatas = new ArrayList<TablesData>();

        // 2、弹出提示框：当前表格总数据xx条，正常数据xx条，异常数据xx条，准备对哪些进行尝试访问？
        int userChoice = JOptionPane.showOptionDialog(null, String.format("当前总数据：%s条，正常数据：%s条，异常数据%s条，需要对哪些进行刷新？", Udatas.size(), Udatas.size() - exceptionDatas.size(), exceptionDatas.size()), "刷新操作选择框", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{"取消", "正常数据", "全部数据", "异常数据"}, "异常数据");
        // 取消
        if (userChoice == 0) return;
            // 正常数据
        else if (userChoice == 1) {
            for (TablesData tablesData : Udatas) {
                // 非异常的加进去
                if (!tablesData.server.contains("Exception")) scanDatas.add(tablesData);
            }
        }
        // 全部数据
        else if (userChoice == 2) scanDatas = Udatas;
            // 异常数据
        else if (userChoice == 3) scanDatas = exceptionDatas;

        // 遍历所有符合的数据
        for (TablesData tablesData : scanDatas) {
            // 1、访问这些目标，重新将数据内容填充到 tablesData里
            // 2、这个访问结果给到项目管理的流程去做一些分析
        }
        // 测试一下
//        TablesData tablesData = Udatas.get(10);
//        tablesData.finger = "id:10 test12312312312";
//        targetTable.repaint();
    }

    public void clickChoiceProjectAction() {

        // 用户对文件的选择 0:不处理 1:覆盖 2:打开 3:创建
        int userChoice;
        // 设置一下过滤器
        FileNameExtensionFilter fileNameExtensionFilter = new FileNameExtensionFilter(".db", "db");
        projectFileChooser.addChoosableFileFilter(fileNameExtensionFilter);
        projectFileChooser.setFileFilter(fileNameExtensionFilter);

        // 2、打开窗口让用户选择文件
        int action = projectFileChooser.showSaveDialog(null);
        // 如果用户点击了取消，就不走处理逻辑
        if (action != JFileChooser.APPROVE_OPTION) return;
        try {
            userChoiceFile = projectFileChooser.getSelectedFile();
            // 如果用户没选择文件，直接退出
            if (userChoiceFile == null) return;

            // 如果文件存在，基于三种选择 覆盖/打开/取消
            if (userChoiceFile.exists()) {
                userChoice = JOptionPane.showOptionDialog(null, String.format("当前选中的文件路径（%s）已经存在，请选择操作方式", userChoiceFile.toString()), "项目选择框", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{"取消", "覆盖", "打开"}, "打开");
                // 取消，直接不处理
                if (userChoice == 0) {
                    return;
                }

                // 覆盖
                if (userChoice == 1) {
                    userChoiceFile.delete();
                    userChoiceFile.createNewFile();
                    // 打开文件的IO流，创建dbhelper
                    dbHelper = new DBHelper(userChoiceFile.toString());
                    config.setDbHelper(dbHelper);
                    // 初始化表格
                    dbHelper.initCreateTable();
                }
                // 打开，就不需要处理，直接往下走就可以
                else if (userChoice == 2) {
                    // 打开文件的IO流，创建dbhelper
                    dbHelper = new DBHelper(userChoiceFile.toString());
                    config.setDbHelper(dbHelper);
                }
            }

            // 如果文件不存在，则直接创建
            else {
                userChoice = 3;
                dbHelper = new DBHelper(userChoiceFile.toString());
                config.setDbHelper(dbHelper);
                dbHelper.initCreateTable();
            }

            // 不管是新建还是覆盖，还是打开一个已有的项目，都要做的内容
            targetTable.getRowSorter().setSortKeys(null);

            // 如果能走到这里，说明肯定是选择了一个文件
            // 0、当用户切换项目的时候，清空projectOpenList里的内容和table里的内容
            {
                projectOpenList.cleanJlistALLInfo();
                // 清空掉url set
                config.getTags().getProjectTableTag().getUrlHashSet().clear();
                // 清空掉ip set
                config.getProjectIPRecord().clear();
                // 清空表格
                this.myTableModel.cleanTable();
                // 更新requests和response
                requestTextEditor.setMessage(new byte[]{}, false);
                responseTextEditor.setMessage(new byte[]{}, true);
            }

            // 1、更新右侧状态栏
            status.setText("当前项目：" + userChoiceFile.getName());
            status.setForeground(Color.blue);
            // 2、恢复其他功能按钮
            buttonEnableChange(true);
            // 3、将db里的数据刷新到界面里
            // 刷新的内容：表格里的数据，目标管理里的数据
            dbHelper.getInfoFromTargetTable(projectOpenList.getDlm(), targetHashSet);
            dbHelper.getInfoFromUrlTable(urlHashSet, config.getProjectIPRecord(),tags.getProjectTableTag());

            // 如果发现加载的targettable没数据，那直接弹出框，让用户
            if (projectOpenList.getDlm().size() == 0) {
                JOptionPane.showMessageDialog(null, "首次创建项目，请先添加目标。");
                projectOpenList.setVisible(true);
            }

            // 2、重新刷新sorter
            // 1、先取消排序
            sorter = null;
            sorter = new TableRowSorter(this.myTableModel);
            targetTable.setRowSorter(sorter);

            // 切换项目时，将历史的任务都清空掉
            config.getProjectManagerUrls().clear();

        } catch (Exception e1) {
            e1.printStackTrace(config.getStderr());
            JOptionPane.showMessageDialog(null, "加载异常 " + e1.getMessage());
            status.setText("加载异常：" + userChoiceFile.toString());
            status.setForeground(Color.red);
            buttonEnableChange(false);
        }
    }

    public class MyTableModel extends AbstractTableModel {

        private List<TablesData> Udatas;

        public MyTableModel(List<TablesData> Udatas) {
            this.Udatas = Udatas;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            if (columnIndex == tableSortList.indexOf("comments")) {
                return true;
            }
            return false;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            TablesData tablesData = Udatas.get(rowIndex);
            // 当用户修改comments时候要做的事情
            if (columnIndex == tableSortList.indexOf("comments")) {
                String userInputComments = ((String) aValue).trim();
                tablesData.setComments(userInputComments);
                fireTableCellUpdated(rowIndex, columnIndex);
                // 还要做一步，更新数据库
                config.getDbHelper().updateUrlTable(tablesData.getUrl(), "comments", Base64.getEncoder().encodeToString(userInputComments.getBytes(StandardCharsets.UTF_8)));
            }
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
                    return datas.domain;
                case 3:
                    return datas.status;
                case 4:
                    return datas.length;
                case 5:
                    return datas.title;
                case 6:
                    return datas.server;
                case 7:
                    return datas.finger;
                case 8:
                    return datas.isCheck;
                case 9:
                    return datas.assetType;
                case 10:
                    return datas.comments;
                case 11:
                    return datas.ip;
                case 12:
                    return datas.updateTime;
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return this.Udatas.size();
        }

        @Override
        public int getColumnCount() {
            return 13;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            /**
             * 影响排序算法
             * @param columnIndex
             * @return
             */
            Class returnValue;
            if (columnIndex >= 0 && columnIndex < getColumnCount()) {
                returnValue = getValueAt(0, columnIndex).getClass();
            } else {
                returnValue = Object.class;
            }

            return returnValue;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return "#";
                case 1:
                    return "url";
                case 2:
                    return "domain";
                case 3:
                    return "status";
                case 4:
                    return "length";
                case 5:
                    return "title";
                case 6:
                    return "server";
                case 7:
                    return "finger";
                case 8:
                    return "isCheck";
                case 9:
                    return "assetType";
                case 10:
                    return "comments";
                case 11:
                    return "ip";
                case 12:
                    return "updateTime";
            }
            return null;
        }

        public void cleanTable() {
            while (Udatas.size() > 0) {
                try {
                    TablesData tablesData = Udatas.remove(0);
                    fireTableDataChanged();
                } catch (Exception e) {
//                    e.printStackTrace();
                }
            }
        }
    }

    public class URLTable extends JTable {

        public URLTable(TableModel tableModel) {
            super(tableModel);
            // 整个表格鼠标监听的模块
            addMouseListener(new MouseListener() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    int id = Integer.parseInt(getValueAt(getSelectedRow(), 0).toString());
                    // 双击 && 左键 && 对着url列
                    if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && getSelectedColumn() == tableSortList.indexOf("url")) {
                        tableLeftDoubleClickAction(e, main2Tag);
                    }

                    // 双击 && 左键 && 对着isCheck
                    if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && getSelectedColumn() == tableSortList.indexOf("isCheck")) {
                        TablesData tablesData = Udatas.get(id);
                        String isCheck = tablesData.isCheck;

                        if (isCheck.equals("未开始")) {
                            isCheck = "进行中";
                        } else if (isCheck.equals("进行中")) {
                            isCheck = "结束";
                        } else if (isCheck.equals("结束")) {
                            isCheck = "再分析";
                        } else if (isCheck.equals("再分析")) {
                            isCheck = "未开始";
                        }

                        // 更新一下库
                        tablesData.setIsCheck(isCheck);
                        config.getDbHelper().updateUrlTable(tablesData.getUrl(), "isCheck", isCheck);
                        targetTable.repaint();
                    }

                    // 双击 && 左键 && 对着 assetType
                    if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && getSelectedColumn() == tableSortList.indexOf("assetType")) {
                        TablesData tablesData = Udatas.get(id);
                        String assetType = tablesData.assetType;

                        if (assetType.equals("未分类")) {
                            assetType = "低价值";
                        } else if (assetType.equals("低价值")) {
                            assetType = "重要目标";
                        } else if (assetType.equals("重要目标")) {
                            assetType = "非目标资产";
                        } else if (assetType.equals("非目标资产")) {
                            assetType = "未分类";
                        }

                        // 更新一下库
                        tablesData.setAssetType(assetType);
                        config.getDbHelper().updateUrlTable(tablesData.getUrl(), "assetType", assetType);
                        targetTable.repaint();
                    }

                    // 双击 && 左键 && 对着 title，折叠request和response
                    if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && getSelectedColumn() == tableSortList.indexOf("title")) {
                        if(count % 2 == 0){
                            tableAndRawPane.setDividerLocation(0.999999);
                        }
                        else{
                            tableAndRawPane.setDividerLocation(0.55);
                        }
                        count += 1;
                    }

                    // 双击 && 左键 && 对着 domain，粘贴url到粘贴板
                    if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && getSelectedColumn() == tableSortList.indexOf("domain")) {
                        int row = getSelectedRow();
                        String url = getValueAt(row, 1).toString();
                        // 获取系统剪切板
                        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                        // 封装文本内容
                        Transferable transferable = new StringSelection(url);
                        // 把文本放到剪切板
                        clipboard.setContents(transferable, null);
                        // 更新一下tips
                        copyTips.setText("复制成功：" + url);
                    }
                }

                @Override
                public void mousePressed(MouseEvent e) {

                }

                @Override
                public void mouseReleased(MouseEvent e) {

                }

                @Override
                public void mouseEntered(MouseEvent e) {

                }

                @Override
                public void mouseExited(MouseEvent e) {

                }
            });
        }

        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = Udatas.get(convertRowIndexToModel(row));
            int messageLength = 50000;
            if (dataEntry.messageInfo.getRequest() != null) {
                requestTextEditor.setMessage(dataEntry.messageInfo.getRequest(), true);
            } else {
                requestTextEditor.setMessage(new byte[]{}, true);
            }

            if (dataEntry.messageInfo.getResponse() != null) {
                responseTextEditor.setMessage(dataEntry.messageInfo.getResponse(), false);
            } else {
                responseTextEditor.setMessage(new byte[]{}, false);
            }

            currentlyDisplayedItem = dataEntry.messageInfo;
            super.changeSelection(row, col, toggle, extend);
        }

        public void tableLeftDoubleClickAction(MouseEvent e, Main2Tag main2Tag) {
            int row = getSelectedRow();
            String url = this.getValueAt(row, 1).toString();
            try {
                Tools.openBrowser(url, main2Tag.getBrowserPathTextField().getText());
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        }
    }

    public void searchButtonAction() {
        String searchString = searchField.getText().trim();
        if (searchString.length() == 0) {
            sorter.setRowFilter(null);
        } else {
            RowFilter rowFilter = RowFilter.regexFilter("(?i)" + searchString);
            sorter.setRowFilter(rowFilter);
        }
    }

    public void buttonEnableChange(boolean status) {
        config.getProjectOtherOptionMenu().getImportItem().setEnabled(status);
        config.getProjectOtherOptionMenu().getExportItem().setEnabled(status);
        config.getProjectOtherOptionMenu().getFreshTitleItem().setEnabled(status);
        config.getProjectOtherOptionMenu().getSetTargetItem().setEnabled(status);
        config.getProjectOtherOptionMenu().getGlobalSearchItem().setEnabled(status);
        config.getProjectOtherOptionMenu().getQuickFofaItem().setEnabled(status);
        config.getProjectOtherOptionMenu().getCopySelectItem().setEnabled(status);

        searchField.setEnabled(status);
        searchButton.setEnabled(status);
    }

    public List<TablesData> getUdatas() {
        return Udatas;
    }

    /**
     * 初次录入使用的add函数
     *
     * @param httpResponse
     * @param messageInfo
     * @return
     */
    public int add(HTTPResponse httpResponse, IHttpRequestResponse messageInfo) {

        int index = (int)this.tags.getTabsName().get("项目管理");
        if (this.tabs.getSelectedIndex() != index) {
            this.tabs.setForegroundAt(index, new Color(255, 102, 51));
        }

        synchronized (this.Udatas) {
            int id = this.Udatas.size();
            String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            // 这里加一个入库流程，因为入库如果抛异常，就不要加到表格里
            boolean insertDBIsSuccess = dbHelper.insertToUrlTable(httpResponse, messageInfo, id, time);
            if (insertDBIsSuccess) {
                // 表格添加
                this.Udatas.add(
                        new TablesData(id, httpResponse.getHost(), httpResponse.getDomain(), httpResponse.getStatus(), httpResponse.getLength(), httpResponse.getTitle(), httpResponse.getServer(), httpResponse.getFingers().stream().map(integer -> integer.toString()).collect(Collectors.joining(",")), httpResponse.getIsCheck(), httpResponse.getAssetType(), httpResponse.getComments(), httpResponse.getIp(), time, messageInfo));
                myTableModel.fireTableRowsInserted(id, id);
            }
            return id;
        }
    }

    /**
     * 加载数据库里数据的add函数
     *
     * @param url
     * @param domain
     * @param status
     * @param length
     * @param title
     * @param server
     * @param finger
     * @param isCheck
     * @param assetType
     * @param comments
     * @param ip
     * @param time
     * @param messageInfo
     * @return
     */
    public int add(String url, String domain, int status, int length, String title, String server, String finger, String isCheck, String assetType, String comments, String ip, String time, IHttpRequestResponse messageInfo) {

        int index = (int)this.tags.getTabsName().get("项目管理");
        if(this.tabs.getSelectedIndex()!=index){
            this.tabs.setForegroundAt(index,new Color(255,102,51));
        }

        synchronized (this.Udatas) {
            int id = this.Udatas.size();
            // 表格添加
            this.Udatas.add(
                    new TablesData(id, url, domain, status, length, title, server, finger, isCheck, assetType, comments, ip, time, messageInfo));
            myTableModel.fireTableRowsInserted(id, id);
            return id;
        }
    }

    public class TablesData {

        final int id;
        final String url;
        final String domain;
        int status;
        int length;
        String title;
        String server;
        String finger;
        String isCheck;
        String assetType;
        String comments;
        String ip;
        String updateTime;
        IHttpRequestResponse messageInfo;

        public TablesData(int id, String url, String domain, int status, int length, String title, String server, String finger, String isCheck, String assetType, String comments, String ip, String updateTime, IHttpRequestResponse messageInfo) {
            this.id = id;
            this.url = url;
            this.domain = domain;
            this.status = status;
            this.length = length;
            this.title = title;
            this.server = server;
            this.finger = finger;
            this.isCheck = isCheck;
            this.assetType = assetType;
            this.comments = comments;
            this.ip = ip;
            this.updateTime = updateTime;
            this.messageInfo = messageInfo;
        }

        public int getId() {
            return id;
        }

        public String getIp() {
            return ip;
        }

        public void setComments(String comments) {
            this.comments = comments;
        }

        public String getUrl() {
            return url;
        }

        public void setIsCheck(String isCheck) {
            this.isCheck = isCheck;
        }

        public void setAssetType(String assetType) {
            this.assetType = assetType;
        }

        public String getAssetType() {
            return assetType;
        }

        public IHttpRequestResponse getMessageInfo() {
            return messageInfo;
        }
    }

    public JCheckBox getRecursionCheckBox() {
        return recursionCheckBox;
    }

    public JButton getChoiceProjectButton() {
        return choiceProjectButton;
    }

    public JPanel getOptionPanel() {
        return optionPanel;
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    public HashSet<String> getTargetHashSet() {
        return targetHashSet;
    }

    public Set<String> getUrlHashSet() {
        return urlHashSet;
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    private void $$$setupUI$$$() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout(0, 0));
        optionPanel = new JPanel();
        optionPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        mainPanel.add(optionPanel, BorderLayout.NORTH);
        choiceProjectButton = new JButton();
        choiceProjectButton.setText("选择项目");
        optionPanel.add(choiceProjectButton);
        otherOptionButton = new JButton();
        otherOptionButton.setText("其他操作");
        optionPanel.add(otherOptionButton);
        searchField = new JTextField();
        searchField.setMinimumSize(new Dimension(150, 25));
        searchField.setPreferredSize(new Dimension(150, 25));
        optionPanel.add(searchField);
        searchButton = new JButton();
        searchButton.setText("查询");
        optionPanel.add(searchButton);
        recursionCheckBox = new JCheckBox();
        recursionCheckBox.setSelected(false);
        recursionCheckBox.setText("暂停爬虫");
        optionPanel.add(recursionCheckBox);
        ipCheckBox = new JCheckBox();
        ipCheckBox.setSelected(true);
        ipCheckBox.setText("IP访问");
        optionPanel.add(ipCheckBox);
        final Spacer spacer1 = new Spacer();
        optionPanel.add(spacer1);
        status = new JLabel();
        status.setText("当前状态：未选择项目");
        optionPanel.add(status);
        final JSeparator separator1 = new JSeparator();
        separator1.setBackground(new Color(-1));
        separator1.setForeground(new Color(-1));
        separator1.setOrientation(1);
        optionPanel.add(separator1);
        backGroundProjectCount = new JLabel();
        backGroundProjectCount.setText("后台任务：");
        optionPanel.add(backGroundProjectCount);
        copyTips = new JLabel();
        copyTips.setText("");
        optionPanel.add(copyTips);
        tableAndRawPane = new JSplitPane();
        tableAndRawPane.setOrientation(0);
        mainPanel.add(tableAndRawPane, BorderLayout.CENTER);
        targetTableScrollPanel = new JScrollPane();
        tableAndRawPane.setLeftComponent(targetTableScrollPanel);
//        targetTable = new JTable();
        targetTableScrollPanel.setViewportView(targetTable);
        requestsAndResponsePanel = new JSplitPane();
        tableAndRawPane.setRightComponent(requestsAndResponsePanel);
    }

    public JLabel getCopyTips() {
        return copyTips;
    }

    public JLabel getBackGroundProjectCount() {
        return backGroundProjectCount;
    }
}

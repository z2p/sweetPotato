package burp.Ui;

import burp.Bootstrap.Config;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.*;
import java.util.HashSet;
import java.util.Set;

public class ProjectOpenList extends JDialog {
    private JPanel mainPanel;
    private JList rootList;
    private JButton addSingleRootButton;
    private JButton andRootsButton;
    private JButton removeButton;
    private JSplitPane listAndButtonPanel;
    private JScrollPane rootListPanel;
    private JPanel buttonPanel;

    private DefaultListModel dlm;
    private Set<String> targetHashSet;
    private Config config;

    public DefaultListModel getDlm() {
        return dlm;
    }

    public ProjectOpenList(Set<String> targetHashSet, Config config) {

        this.targetHashSet = targetHashSet;
        this.config = config;
        // 初始化
        $$$setupUI$$$();
        // 自定义的初始化
        init();
    }

    public void init() {
        // 主面板设置一定的间隔
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        // 设置分隔距离
        listAndButtonPanel.setDividerLocation(0.9);
        listAndButtonPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                listAndButtonPanel.setDividerLocation(0.9);
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

        // 设置DefaultListModel去管理JList的数据
        dlm = new DefaultListModel();
        rootList.setModel(dlm);

        // 当用户点击添加的按钮
        addSingleRootButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addSingleRootButtonAction();
            }
        });

        // 当用户点击移除的按钮
        removeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectIndex = rootList.getSelectedIndex();
                if (selectIndex == -1) {
                    return;
                }
                cleanJlistInfo(selectIndex, dlm, targetHashSet);
            }
        });

        // 当用户对页面按下一些特殊键盘位
        rootList.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {

            }

            @Override
            public void keyPressed(KeyEvent e) {
                // 10 = 回车
                if (e.getKeyCode() == 10) {
                    addSingleRootButtonAction();
                }
                // 27 = Esc
                else if (e.getKeyCode() == 27) {
                    setVisible(false);
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {

            }
        });

        this.setTitle("根域名配置");
        this.setSize(450, 400);
        this.setLocationRelativeTo(null);
        this.add(mainPanel);
    }

    /**
     * 自定义清空jList里的某条数据
     */
    public void cleanJlistInfo(int selectIndex, DefaultListModel dlm, Set<String> targetHashSet) {
        Object selectIndexValue = dlm.getElementAt(selectIndex);
        dlm.remove(selectIndex);
        targetHashSet.remove(selectIndexValue);
    }

    /**
     * 自定义清空整个jlist
     */
    public void cleanJlistALLInfo() {
        while (dlm.size() > 0) {
            dlm.remove(0);
        }
        targetHashSet.clear();
    }

    public void addSingleRootButtonAction() {
        String domain = JOptionPane.showInputDialog(mainPanel, "请输入要添加的根域名（如：xxxx.com）");
        if (domain == null || domain.trim().length() == 0) {
        } else {
            // 遍历当前的数据，评估是否需要添加数据
            for (int i = 0; i < dlm.size(); i++) {
                String saveInfo = dlm.getElementAt(i).toString();
                if (saveInfo.equals(domain.trim())) {
                    JOptionPane.showMessageDialog(mainPanel, "添加失败：已存在该记录！");
                    return;
                }
            }

            domain = domain.trim();
            // 如果输入的域名是xxx.com，则改成 .xxx.com
            if (!domain.startsWith(".")) domain = "." + domain;
            config.getDbHelper().insertToTargetTable(dlm.size() + 1, domain);
            targetHashSet.add(domain);
            dlm.addElement(domain);
        }
    }

    public static void main(String[] args) {
//        JFrame frame = new JFrame("projectOpenList");
//        frame.setContentPane(new ProjectOpenList().mainPanel);
//        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        frame.pack();
//        frame.setVisible(true);
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout(0, 0));
        listAndButtonPanel = new JSplitPane();
        listAndButtonPanel.setOrientation(0);
        mainPanel.add(listAndButtonPanel, BorderLayout.CENTER);
        rootListPanel = new JScrollPane();
        listAndButtonPanel.setLeftComponent(rootListPanel);
        rootListPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        rootList = new JList();
        rootList.putClientProperty("List.isFileList", Boolean.TRUE);
        rootList.putClientProperty("html.disable", Boolean.FALSE);
        rootListPanel.setViewportView(rootList);
        buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        listAndButtonPanel.setRightComponent(buttonPanel);
        buttonPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        addSingleRootButton = new JButton();
        addSingleRootButton.setText("添加（单个）↵");
        buttonPanel.add(addSingleRootButton);
        andRootsButton = new JButton();
        andRootsButton.setText("添加（多个）");
        buttonPanel.add(andRootsButton);
        removeButton = new JButton();
        removeButton.setText("移除");
        buttonPanel.add(removeButton);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }

}

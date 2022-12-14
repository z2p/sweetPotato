package burp.Ui;

import burp.Bootstrap.Config;
import burp.Bootstrap.Tools;
import burp.IBurpExtenderCallbacks;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.*;
import java.io.File;

public class Main2Tag {

    private IBurpExtenderCallbacks callbacks;
    private Config config;
    private boolean helpButtonStatus = false;

    private JPanel mainPanel;
    private JCheckBox globalCheckBox;
    private JButton helpButton;
    private JCheckBox addRememberMeButton;
    private JCheckBox responseBeautyCheckBox;
    private JCheckBox statusTo200CheckBox;
    private JCheckBox wechatFakeCheckBox;
    private JCheckBox disableJSCheckBox;
    private JCheckBox chunkedBox;
    private JTextField browserPathTextField;
    private JTextField fingerPathTextField;
    private JTextField infoPathTextField;
    private JCheckBox passiveAllCheckBox;
    private JCheckBox SSRFCheckBox;
    private JCheckBox listDirectoryCheckBox;
    private JCheckBox infoLeakCheckBox;
    private JCheckBox fingerCheckBox;
    private JCheckBox wafCheckBox;
    private JCheckBox languageCheckBox;
    private JCheckBox sensitiveCheckBox;
    private JCheckBox activeAllCheckBox;
    private JCheckBox unexistsPathCheckBox;
    private JCheckBox activeListDirectoryCheckBox;
    private JCheckBox activeJsonErrorTestCheckBox;
    private JCheckBox exceptionParaCheckBox;
    private JCheckBox backupFileCheckBox;
    private JCheckBox infoFileCheckBox;
    private JCheckBox activeFingerCheckBox;
    private JCheckBox knownFingerDirScanCheckBox;
    private JTextField pocPathTextField;
    private JButton reloadConfigButton;
    private JPanel globalPanel;
    private JSplitPane AllSpiltPanel;
    private JSplitPane northSplitPanel;
    private JSplitPane southSpiltPanel;
    private JPanel northLeftPanel;
    private JPanel northRightPanel;
    private JPanel southLeftPanel;
    private JPanel southRightPanel;
    private JPanel addRememberMePanel;
    private JLabel addRememberMeHelp;
    private JPanel responseBeautyPanel;
    private JLabel responseBeautyHelp;
    private JPanel statusTo200Panel;
    private JLabel statusTo200Help;
    private JPanel wechatFakePanel;
    private JLabel wechatFakeHelp;
    private JPanel disbleJSPanel;
    private JLabel disableJSHelp;
    private JPanel chunkedPanel;
    private JLabel chunkedLabel;
    private JPanel browserSettingPanel;
    private JLabel browserLabel;
    private JLabel browserHelp;
    private JPanel fingerPathSettingPanel;
    private JLabel fingerPathLabel;
    private JLabel fingerPathHelp;
    private JPanel infoPathPanel;
    private JLabel infoPathLabel;
    private JLabel infoPathHelp;
    private JPanel buttonPanel;
    private JLabel Status;
    private JPanel passiveAllPanel;
    private JLabel passiveHelp;
    private JPanel SSRFPanel;
    private JLabel SSRFHelp;
    private JPanel listDirectoryPanel;
    private JLabel listDirectoryHelp;
    private JPanel infoLeakPanel;
    private JLabel infoLeakHelp;
    private JPanel fingerPanel;
    private JLabel fingerHelp;
    private JPanel wafPanel;
    private JLabel wafHelp;
    private JPanel languagePanel;
    private JLabel languageHelp;
    private JPanel sensitivePathPanel;
    private JLabel sensitiveHelp;
    private JPanel activeAllPanel;
    private JLabel activePanelHelp;
    private JPanel unexistsPathPanel;
    private JLabel unexistsPathHelp;
    private JPanel activeListDirectoryPanel;
    private JLabel activeListDirectoryLabel;
    private JPanel activeJsonErrorTestPanel;
    private JLabel activeJsonErrorTestLabel;
    private JPanel exceptionParaPanel;
    private JLabel exceptionParaHelp;
    private JPanel backupFilePanel;
    private JLabel backupFileHelp;
    private JPanel infoFilePanel;
    private JLabel infoFileHelp;
    private JPanel activeFingerPanel;
    private JLabel activeFingerHelp;
    private JPanel knownFingerDirScanPanel;
    private JLabel knownFingerDirScanHelp;
    private JPanel activeProxyPanel;
    private JLabel activeProxyLabel;
    private JComboBox activeProxyComboBox;
    private JTextField activeProxyTextField;
    private JPanel pocPathPanel;
    private JLabel pocPathLabel;
    private JLabel pocPathHelp;
    private JCheckBox flushBrowserCheckBox;
    private JPanel flushBrowserPanel;
    private JLabel flushBrowserHelp;
    private JPanel dirHeaderPanel;
    private JCheckBox dirHeaderCheckBox;
    private JRadioButton dirHeaderAddButton;
    private JRadioButton dirHeaderRecoverButton;
    private JCheckBox dirHeaderWrap;
    private JLabel dirHeaderHelp;
    private JScrollPane dirHeaderScrollPane;
    private JTextArea dirHeaderTextArea;
    private JPanel backupPathPanel;
    private JLabel backupPathLabel;
    private JTextField backupPathTextField;
    private JLabel backupPathHelp;
    private JPanel passiveDetailPanel;
    private JPanel activeDetailPanel;
    private JPanel dirHeaderOptionPanel;
    private JCheckBox userAgentCheckBox;
    private JRadioButton chromeRadioButton;
    private JRadioButton firefoxRadioButton;
    private JRadioButton IE7RadioButton;
    private JRadioButton iphoneRadioButton;
    private JPanel userAgentPanel;
    private JLabel userAgentHelp;
    private JLabel fingerChangeTips;
    private JLabel infoChangeTips;
    private JLabel pocChangeTips;
    private JLabel backupChangeTips;


    public Main2Tag(JTabbedPane tabs, Config config){
        this.config = config;
        this.callbacks = config.getCallbacks();

        $$$setupUI$$$(); // ???????????????????????????
        this.Status.setText("?????????????????????????????????x??????xxxxx");
        this.fingerPathTextField.setText(config.getJarPath() + "resources" + File.separator + "finger.json");
        this.infoPathTextField.setText(config.getJarPath() + "resources"  + File.separator + "infoLeakFinger.json");
        this.pocPathTextField.setText(config.getJarPath() + "resources"  + File.separator + "pocFinger.json");
        this.backupPathTextField.setText(config.getJarPath() + "resources"  + File.separator + "backupFileDict.json");

        this.activeListDirectoryCheckBox.setSelected(true);

        // ??????????????????
        northSplitPanel.setDividerLocation(0.5);
        northSplitPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                northSplitPanel.setDividerLocation(0.5);
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
        southSpiltPanel.setDividerLocation(0.5);
        southSpiltPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                southSpiltPanel.setDividerLocation(0.5);
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
        AllSpiltPanel.setDividerLocation(0.5);
        AllSpiltPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                AllSpiltPanel.setDividerLocation(0.5);
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

        // ??????????????????????????????????????????
        browserHelp.setVisible(helpButtonStatus);
        disableJSHelp.setVisible(helpButtonStatus);
        fingerPathHelp.setVisible(helpButtonStatus);
        infoPathHelp.setVisible(helpButtonStatus);
        wechatFakeHelp.setVisible(helpButtonStatus);
        flushBrowserHelp.setVisible(helpButtonStatus);
        statusTo200Help.setVisible(helpButtonStatus);
        responseBeautyHelp.setVisible(helpButtonStatus);
        addRememberMeHelp.setVisible(helpButtonStatus);
        listDirectoryHelp.setVisible(helpButtonStatus);
        SSRFHelp.setVisible(helpButtonStatus);
        infoLeakHelp.setVisible(helpButtonStatus);
        fingerHelp.setVisible(helpButtonStatus);
        activePanelHelp.setVisible(helpButtonStatus);
        unexistsPathHelp.setVisible(helpButtonStatus);
        backupFileHelp.setVisible(helpButtonStatus);
        infoFileHelp.setVisible(helpButtonStatus);
        dirHeaderHelp.setVisible(helpButtonStatus);
        chunkedLabel.setVisible(helpButtonStatus);
        wafHelp.setVisible(helpButtonStatus);
        languageHelp.setVisible(helpButtonStatus);
        sensitiveHelp.setVisible(helpButtonStatus);
        exceptionParaHelp.setVisible(helpButtonStatus);
        activeFingerHelp.setVisible(helpButtonStatus);
        knownFingerDirScanHelp.setVisible(helpButtonStatus);
        passiveHelp.setVisible(helpButtonStatus);
        activeListDirectoryLabel.setVisible(helpButtonStatus);
        pocPathHelp.setVisible(helpButtonStatus);
        backupPathHelp.setVisible(helpButtonStatus);
        activeJsonErrorTestLabel.setVisible(helpButtonStatus);
        userAgentHelp.setVisible(helpButtonStatus);

        // ??????????????????????????? helpButton??????????????????????????????
        helpButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                browserHelp.setVisible(!helpButtonStatus);
                disableJSHelp.setVisible(!helpButtonStatus);
                fingerPathHelp.setVisible(!helpButtonStatus);
                infoPathHelp.setVisible(!helpButtonStatus);
                wechatFakeHelp.setVisible(!helpButtonStatus);
                flushBrowserHelp.setVisible(!helpButtonStatus);
                statusTo200Help.setVisible(!helpButtonStatus);
                responseBeautyHelp.setVisible(!helpButtonStatus);
                addRememberMeHelp.setVisible(!helpButtonStatus);
                listDirectoryHelp.setVisible(!helpButtonStatus);
                SSRFHelp.setVisible(!helpButtonStatus);
                infoLeakHelp.setVisible(!helpButtonStatus);
                fingerHelp.setVisible(!helpButtonStatus);
                activePanelHelp.setVisible(!helpButtonStatus);
                unexistsPathHelp.setVisible(!helpButtonStatus);
                backupFileHelp.setVisible(!helpButtonStatus);
                infoFileHelp.setVisible(!helpButtonStatus);
                dirHeaderHelp.setVisible(!helpButtonStatus);
                chunkedLabel.setVisible(!helpButtonStatus);
                wafHelp.setVisible(!helpButtonStatus);
                languageHelp.setVisible(!helpButtonStatus);
                sensitiveHelp.setVisible(!helpButtonStatus);
                exceptionParaHelp.setVisible(!helpButtonStatus);
                activeFingerHelp.setVisible(!helpButtonStatus);
                knownFingerDirScanHelp.setVisible(!helpButtonStatus);
                passiveHelp.setVisible(!helpButtonStatus);
                activeListDirectoryLabel.setVisible(!helpButtonStatus);
                pocPathHelp.setVisible(!helpButtonStatus);
                backupPathHelp.setVisible(!helpButtonStatus);
                activeJsonErrorTestLabel.setVisible(!helpButtonStatus);
                userAgentHelp.setVisible(!helpButtonStatus);

                if(helpButtonStatus==true){
                    helpButtonStatus = false;
                }else{
                    helpButtonStatus = true;
                }
            }
        });
        // ????????????????????????
        Status.setEnabled(false);
        // ????????????????????? ?????? ???????????????
        {
            // ?????????????????????????????????
            globalCheckBox.setSelected(true);
            // ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? ?????? ?????????false
            globalCheckBox.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    setGlobalSetting(globalCheckBox.isSelected());
                }
            });

            // ??????????????????????????????????????????????????????
            dirHeaderCheckBox.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    dirHeaderAction(dirHeaderCheckBox.isSelected());
                }
            });

            dirHeaderWrap.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    dirHeaderTextArea.setLineWrap(dirHeaderWrap.isSelected());
                }
            });

            // ???????????????
            dirHeaderAddButton.setEnabled(false);
            dirHeaderRecoverButton.setEnabled(false);
            dirHeaderWrap.setEnabled(false);
            chromeRadioButton.setEnabled(false);
            firefoxRadioButton.setEnabled(false);
            IE7RadioButton.setEnabled(false);
            iphoneRadioButton.setEnabled(false);
            changeTips(false);

            fingerPathTextField.addKeyListener(new KeyListener() {
                @Override
                public void keyTyped(KeyEvent e) {
                    fingerChangeTips.setVisible(true);
                }

                @Override
                public void keyPressed(KeyEvent e) {

                }

                @Override
                public void keyReleased(KeyEvent e) {

                }
            });

            infoPathTextField.addKeyListener(new KeyListener() {
                @Override
                public void keyTyped(KeyEvent e) {
                    infoChangeTips.setVisible(true);
                }

                @Override
                public void keyPressed(KeyEvent e) {

                }

                @Override
                public void keyReleased(KeyEvent e) {

                }
            });

            pocPathTextField.addKeyListener(new KeyListener() {
                @Override
                public void keyTyped(KeyEvent e) {
                    pocChangeTips.setVisible(true);
                }

                @Override
                public void keyPressed(KeyEvent e) {

                }

                @Override
                public void keyReleased(KeyEvent e) {

                }
            });

            backupPathTextField.addKeyListener(new KeyListener() {
                @Override
                public void keyTyped(KeyEvent e) {
                    backupChangeTips.setVisible(true);
                }

                @Override
                public void keyPressed(KeyEvent e) {

                }

                @Override
                public void keyReleased(KeyEvent e) {

                }
            });

            // ?????? ??????????????????????????????
            ButtonGroup bg = new ButtonGroup();
            bg.add(dirHeaderAddButton);
            bg.add(dirHeaderRecoverButton);

            // ??????User-agent???buttongroup
            ButtonGroup userAgentbg = new ButtonGroup();
            userAgentbg.add(chromeRadioButton);
            userAgentbg.add(firefoxRadioButton);
            userAgentbg.add(IE7RadioButton);
            userAgentbg.add(iphoneRadioButton);

            // User-Agent?????????
            userAgentCheckBox.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    userAgentAction(userAgentCheckBox.isSelected());
                }
            });
            userAgentCheckBox.setSelected(true);
            userAgentAction(true);

            //
            /**
             * ?????????????????????????????????????????????????????????????????????2????????????
             * 1?????????
             * 2???????????????
             *
             * ???2????????????????????????
             * 3????????????????????????????????????????????????/??????
             */
            reloadConfigButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    try{
                        config.setFingerJsonInfo(Tools.getJSONObject(getFingerPathTextField().getText()));
                        config.setInfoLeakJsonInfo(Tools.getJSONObject(getInfoPathTextField().getText()));
                        Status.setText("????????????????????????????????? " + config.getFingerJsonInfo().size() + "???");
                        // ??????????????????
                        changeTips(false);

                    }catch (Exception e1){
                        Status.setText("??????????????????????????????????????????" + e1.getMessage());
                    }

                }
            });

        }
        // ????????????????????? ?????? ???????????????
        {
            // ?????????????????????????????????
            passiveAllCheckBox.setSelected(true);
            // ???????????????????????????????????????
            sensitiveCheckBox.setSelected(true);
            listDirectoryCheckBox.setSelected(true);
            infoLeakCheckBox.setSelected(true);
            fingerCheckBox.setSelected(true);
            languageCheckBox.setSelected(true);
            // ???????????????????????????????????????
            SSRFCheckBox.setSelected(false);

            passiveAllCheckBox.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    setPassiveSetting(passiveAllCheckBox.isSelected());
                }
            });
        }
        // ????????????????????? ?????? ???????????????
        {
            // ??????4????????????????????????
            // ?????????????????????????????????
            activeAllCheckBox.setSelected(true);
            // ????????????????????????????????????
            unexistsPathCheckBox.setSelected(true);
            // ???????????? json
            activeJsonErrorTestCheckBox.setSelected(true);
            // ????????? ???????????????
            activeListDirectoryCheckBox.setSelected(true);

            activeAllCheckBox.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    setActiveSetting(activeAllCheckBox.isSelected());
                }
            });
        }

        // ???????????????tag
        tabs.addTab("????????????",mainPanel);
    }

    private void $$$setupUI$$$() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout(0, 0));
        globalPanel = new JPanel();
        globalPanel.setLayout(new BorderLayout(0, 0));
        mainPanel.add(globalPanel, BorderLayout.NORTH);
        globalCheckBox = new JCheckBox();
        globalCheckBox.setSelected(true);
        globalCheckBox.setText("????????????");
        globalPanel.add(globalCheckBox, BorderLayout.WEST);
        helpButton = new JButton();
        helpButton.setText("??????");
        globalPanel.add(helpButton, BorderLayout.EAST);
        AllSpiltPanel = new JSplitPane();
        AllSpiltPanel.setOrientation(0);
        AllSpiltPanel.setResizeWeight(0.5);
        mainPanel.add(AllSpiltPanel, BorderLayout.CENTER);
        northSplitPanel = new JSplitPane();
        northSplitPanel.setResizeWeight(0.5);
        AllSpiltPanel.setLeftComponent(northSplitPanel);
        northLeftPanel = new JPanel();
        northLeftPanel.setLayout(new FormLayout("fill:max(d;4px):noGrow,left:4dlu:noGrow,fill:d:grow", "center:d:noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow"));
        northSplitPanel.setLeftComponent(northLeftPanel);
        northLeftPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        addRememberMePanel = new JPanel();
        addRememberMePanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        CellConstraints cc = new CellConstraints();
        northLeftPanel.add(addRememberMePanel, cc.xy(3, 1, CellConstraints.LEFT, CellConstraints.DEFAULT));
        addRememberMeButton = new JCheckBox();
        addRememberMeButton.setText("??????RememberMe???Cookie");
        addRememberMePanel.add(addRememberMeButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        addRememberMeHelp = new JLabel();
        addRememberMeHelp.setForeground(new Color(-65536));
        addRememberMeHelp.setText("  cookie??????remember???????????????host??????????????????");
        addRememberMePanel.add(addRememberMeHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        responseBeautyPanel = new JPanel();
        responseBeautyPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(responseBeautyPanel, cc.xy(3, 3, CellConstraints.LEFT, CellConstraints.DEFAULT));
        responseBeautyCheckBox = new JCheckBox();
        responseBeautyCheckBox.setText("???????????????????????????????????????????????????");
        responseBeautyPanel.add(responseBeautyCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        responseBeautyHelp = new JLabel();
        responseBeautyHelp.setForeground(new Color(-65536));
        responseBeautyHelp.setText("  ????????????json?????????unicode???????????????????????????");
        responseBeautyPanel.add(responseBeautyHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        northLeftPanel.add(spacer1, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        statusTo200Panel = new JPanel();
        statusTo200Panel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(statusTo200Panel, cc.xy(3, 5, CellConstraints.LEFT, CellConstraints.DEFAULT));
        statusTo200CheckBox = new JCheckBox();
        statusTo200CheckBox.setText("????????????????????????200");
        statusTo200Panel.add(statusTo200CheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        statusTo200Help = new JLabel();
        statusTo200Help.setForeground(new Color(-65536));
        statusTo200Help.setText("  ??????????????????302???????????????");
        statusTo200Panel.add(statusTo200Help, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        wechatFakePanel = new JPanel();
        wechatFakePanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(wechatFakePanel, cc.xy(3, 7, CellConstraints.LEFT, CellConstraints.DEFAULT));
        wechatFakeCheckBox = new JCheckBox();
        wechatFakeCheckBox.setText("????????????????????????????????????????????????");
        wechatFakePanel.add(wechatFakeCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        wechatFakeHelp = new JLabel();
        wechatFakeHelp.setForeground(new Color(-65536));
        wechatFakeHelp.setText("  ??????????????????????????????????????????????????????????????????????????????????????????");
        wechatFakePanel.add(wechatFakeHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        disbleJSPanel = new JPanel();
        disbleJSPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(disbleJSPanel, cc.xy(3, 11, CellConstraints.LEFT, CellConstraints.DEFAULT));
        disableJSCheckBox = new JCheckBox();
        disableJSCheckBox.setText("??????js?????????????????????");
        disbleJSPanel.add(disableJSCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        disableJSHelp = new JLabel();
        disableJSHelp.setForeground(new Color(-65536));
        disableJSHelp.setText("????????????js????????????");
        disbleJSPanel.add(disableJSHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chunkedPanel = new JPanel();
        chunkedPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(chunkedPanel, cc.xy(3, 13, CellConstraints.LEFT, CellConstraints.DEFAULT));
        chunkedBox = new JCheckBox();
        chunkedBox.setText("????????????chunked???????????????");
        chunkedPanel.add(chunkedBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chunkedLabel = new JLabel();
        chunkedLabel.setForeground(new Color(-65536));
        chunkedLabel.setText("  ??????????????????????????????chunked??????????????????????????????sql???????????????");
        chunkedPanel.add(chunkedLabel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        browserSettingPanel = new JPanel();
        browserSettingPanel.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(browserSettingPanel, cc.xy(3, 15, CellConstraints.LEFT, CellConstraints.DEFAULT));
        browserLabel = new JLabel();
        browserLabel.setText("?????????????????? ");
        browserSettingPanel.add(browserLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        browserPathTextField = new JTextField();
        browserPathTextField.setText("/Applications/Firefox.app/Contents/MacOS/firefox");
        browserSettingPanel.add(browserPathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(400, 25), null, 1, false));
        browserHelp = new JLabel();
        browserHelp.setForeground(new Color(-65536));
        browserHelp.setText("????????????????????????");
        browserSettingPanel.add(browserHelp, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        fingerPathSettingPanel = new JPanel();
        fingerPathSettingPanel.setLayout(new GridLayoutManager(1, 4, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(fingerPathSettingPanel, cc.xy(3, 17, CellConstraints.LEFT, CellConstraints.DEFAULT));
        fingerPathLabel = new JLabel();
        fingerPathLabel.setText("?????????????????????");
        fingerPathSettingPanel.add(fingerPathLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        fingerPathTextField = new JTextField();
        fingerPathTextField.setText("/Users/z2p/notes2/????????????/public/finger.json");
        fingerPathSettingPanel.add(fingerPathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(400, 25), null, 0, false));
        fingerPathHelp = new JLabel();
        fingerPathHelp.setForeground(new Color(-65536));
        fingerPathHelp.setText("?????????????????????????????????");
        fingerPathSettingPanel.add(fingerPathHelp, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        fingerChangeTips = new JLabel();
        fingerChangeTips.setForeground(new Color(-8080897));
        fingerChangeTips.setText("???????????????????????????");
        fingerPathSettingPanel.add(fingerChangeTips, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        infoPathPanel = new JPanel();
        infoPathPanel.setLayout(new GridLayoutManager(1, 4, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(infoPathPanel, cc.xy(3, 19, CellConstraints.LEFT, CellConstraints.DEFAULT));
        infoPathLabel = new JLabel();
        infoPathLabel.setText("?????????????????????");
        infoPathPanel.add(infoPathLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        infoPathTextField = new JTextField();
        infoPathTextField.setText("/Users/z2p/notes2/????????????/public/infoLeakFinger.json");
        infoPathPanel.add(infoPathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(400, 25), null, 0, false));
        infoPathHelp = new JLabel();
        infoPathHelp.setForeground(new Color(-65536));
        infoPathHelp.setText("?????????????????????????????????");
        infoPathPanel.add(infoPathHelp, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        infoChangeTips = new JLabel();
        infoChangeTips.setForeground(new Color(-8080897));
        infoChangeTips.setText("???????????????????????????");
        infoPathPanel.add(infoChangeTips, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pocPathPanel = new JPanel();
        pocPathPanel.setLayout(new GridLayoutManager(1, 4, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(pocPathPanel, cc.xy(3, 21, CellConstraints.LEFT, CellConstraints.DEFAULT));
        pocPathLabel = new JLabel();
        pocPathLabel.setText("?????????????????????");
        pocPathPanel.add(pocPathLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pocPathTextField = new JTextField();
        pocPathTextField.setText("/Users/z2p/notes2/????????????/public/pocFinger.json");
        pocPathPanel.add(pocPathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(400, 25), null, 0, false));
        pocPathHelp = new JLabel();
        pocPathHelp.setForeground(new Color(-65536));
        pocPathHelp.setText("?????????????????????????????????");
        pocPathPanel.add(pocPathHelp, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pocChangeTips = new JLabel();
        pocChangeTips.setForeground(new Color(-8080897));
        pocChangeTips.setText("???????????????????????????");
        pocPathPanel.add(pocChangeTips, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(buttonPanel, cc.xy(3, 25, CellConstraints.LEFT, CellConstraints.DEFAULT));
        reloadConfigButton = new JButton();
        reloadConfigButton.setText("????????????????????????");
        buttonPanel.add(reloadConfigButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        Status = new JLabel();
        Status.setText("?????????????????????????????????x??????xxxxx");
        buttonPanel.add(Status, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        flushBrowserPanel = new JPanel();
        flushBrowserPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(flushBrowserPanel, cc.xy(3, 9, CellConstraints.LEFT, CellConstraints.DEFAULT));
        flushBrowserCheckBox = new JCheckBox();
        flushBrowserCheckBox.setSelected(true);
        flushBrowserCheckBox.setText("???????????????????????????");
        flushBrowserPanel.add(flushBrowserCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        flushBrowserHelp = new JLabel();
        flushBrowserHelp.setForeground(new Color(-65536));
        flushBrowserHelp.setText("  ?????????????????????????????????????????????????????????????????????????????????");
        flushBrowserPanel.add(flushBrowserHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        backupPathPanel = new JPanel();
        backupPathPanel.setLayout(new GridLayoutManager(1, 4, new Insets(0, 0, 0, 0), -1, -1));
        northLeftPanel.add(backupPathPanel, cc.xy(3, 23, CellConstraints.LEFT, CellConstraints.DEFAULT));
        backupPathLabel = new JLabel();
        backupPathLabel.setText("?????????????????????");
        backupPathPanel.add(backupPathLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        backupPathTextField = new JTextField();
        backupPathTextField.setText("/Users/z2p/notes2/????????????/public/backupFileDict.json");
        backupPathPanel.add(backupPathTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(400, 25), null, 0, false));
        backupPathHelp = new JLabel();
        backupPathHelp.setForeground(new Color(-65536));
        backupPathHelp.setText("?????????????????????????????????");
        backupPathPanel.add(backupPathHelp, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        backupChangeTips = new JLabel();
        backupChangeTips.setForeground(new Color(-8080897));
        backupChangeTips.setText("???????????????????????????");
        backupPathPanel.add(backupChangeTips, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        northRightPanel = new JPanel();
        northRightPanel.setLayout(new FormLayout("fill:d:grow", "center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow"));
        northRightPanel.setAlignmentX(1.0f);
        northRightPanel.setAlignmentY(1.0f);
        northSplitPanel.setRightComponent(northRightPanel);
        northRightPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        activeProxyPanel = new JPanel();
        activeProxyPanel.setLayout(new FormLayout("fill:max(d;4px):noGrow,left:4dlu:noGrow,fill:max(d;4px):noGrow,left:4dlu:noGrow,fill:d:grow", "center:d:grow"));
        northRightPanel.add(activeProxyPanel, cc.xy(1, 3, CellConstraints.LEFT, CellConstraints.DEFAULT));
        activeProxyLabel = new JLabel();
        activeProxyLabel.setText("  ??????????????????: (?????????)");
        activeProxyPanel.add(activeProxyLabel, cc.xy(1, 1));
        activeProxyComboBox = new JComboBox();
        activeProxyComboBox.setEnabled(false);
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        defaultComboBoxModel1.addElement("?????????");
        defaultComboBoxModel1.addElement("sock5");
        defaultComboBoxModel1.addElement("http");
        defaultComboBoxModel1.addElement("https");
        activeProxyComboBox.setModel(defaultComboBoxModel1);
        activeProxyPanel.add(activeProxyComboBox, cc.xy(3, 1));
        activeProxyTextField = new JTextField();
        activeProxyTextField.setEditable(false);
        activeProxyTextField.setEnabled(false);
        activeProxyTextField.setPreferredSize(new Dimension(300, 30));
        activeProxyTextField.setVisible(true);
        activeProxyPanel.add(activeProxyTextField, cc.xy(5, 1, CellConstraints.CENTER, CellConstraints.DEFAULT));
        dirHeaderPanel = new JPanel();
        dirHeaderPanel.setLayout(new BorderLayout(0, 0));
        northRightPanel.add(dirHeaderPanel, cc.xy(1, 1));
        dirHeaderOptionPanel = new JPanel();
        dirHeaderOptionPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        dirHeaderPanel.add(dirHeaderOptionPanel, BorderLayout.NORTH);
        dirHeaderCheckBox = new JCheckBox();
        dirHeaderCheckBox.setEnabled(true);
        dirHeaderCheckBox.setText("?????????????????????");
        dirHeaderCheckBox.setVisible(true);
        dirHeaderOptionPanel.add(dirHeaderCheckBox);
        final Spacer spacer2 = new Spacer();
        dirHeaderOptionPanel.add(spacer2);
        dirHeaderAddButton = new JRadioButton();
        dirHeaderAddButton.setSelected(true);
        dirHeaderAddButton.setText("??????");
        dirHeaderOptionPanel.add(dirHeaderAddButton);
        dirHeaderRecoverButton = new JRadioButton();
        dirHeaderRecoverButton.setText("??????");
        dirHeaderOptionPanel.add(dirHeaderRecoverButton);
        dirHeaderWrap = new JCheckBox();
        dirHeaderWrap.setText("????????????");
        dirHeaderOptionPanel.add(dirHeaderWrap);
        dirHeaderHelp = new JLabel();
        dirHeaderHelp.setForeground(new Color(-65536));
        dirHeaderHelp.setText("???????????????????????????????????????????????????????????????????????????????????????");
        dirHeaderHelp.setVisible(false);
        dirHeaderOptionPanel.add(dirHeaderHelp);
        dirHeaderScrollPane = new JScrollPane();
        dirHeaderScrollPane.setEnabled(false);
        dirHeaderScrollPane.setVisible(true);
        dirHeaderPanel.add(dirHeaderScrollPane, BorderLayout.CENTER);
        dirHeaderScrollPane.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        dirHeaderTextArea = new JTextArea();
        dirHeaderTextArea.setColumns(12);
        dirHeaderTextArea.setEditable(false);
        dirHeaderTextArea.setEnabled(false);
        dirHeaderTextArea.setRows(8);
        dirHeaderTextArea.setVisible(true);
        dirHeaderScrollPane.setViewportView(dirHeaderTextArea);
        userAgentPanel = new JPanel();
        userAgentPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
        northRightPanel.add(userAgentPanel, cc.xy(1, 5, CellConstraints.LEFT, CellConstraints.DEFAULT));
        userAgentCheckBox = new JCheckBox();
        userAgentCheckBox.setText("??????User-Agent");
        userAgentPanel.add(userAgentCheckBox);
        chromeRadioButton = new JRadioButton();
        chromeRadioButton.setSelected(true);
        chromeRadioButton.setText("Chrome");
        userAgentPanel.add(chromeRadioButton);
        firefoxRadioButton = new JRadioButton();
        firefoxRadioButton.setText("Firefox");
        userAgentPanel.add(firefoxRadioButton);
        IE7RadioButton = new JRadioButton();
        IE7RadioButton.setText("IE7");
        userAgentPanel.add(IE7RadioButton);
        iphoneRadioButton = new JRadioButton();
        iphoneRadioButton.setText("iphone");
        userAgentPanel.add(iphoneRadioButton);
        userAgentHelp = new JLabel();
        userAgentHelp.setForeground(new Color(-65536));
        userAgentHelp.setText("???????????????????????????");
        userAgentPanel.add(userAgentHelp);
        southSpiltPanel = new JSplitPane();
        southSpiltPanel.setResizeWeight(0.5);
        AllSpiltPanel.setRightComponent(southSpiltPanel);
        southLeftPanel = new JPanel();
        southLeftPanel.setLayout(new BorderLayout(0, 0));
        southSpiltPanel.setLeftComponent(southLeftPanel);
        southLeftPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        passiveAllPanel = new JPanel();
        passiveAllPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        southLeftPanel.add(passiveAllPanel, BorderLayout.NORTH);
        passiveAllPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        passiveAllCheckBox = new JCheckBox();
        passiveAllCheckBox.setSelected(true);
        passiveAllCheckBox.setText("??????????????????");
        passiveAllPanel.add(passiveAllCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        passiveHelp = new JLabel();
        passiveHelp.setForeground(new Color(-65536));
        passiveHelp.setText("   ??????????????????????????????????????????????????????????????????");
        passiveAllPanel.add(passiveHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        passiveDetailPanel = new JPanel();
        passiveDetailPanel.setLayout(new FormLayout("fill:max(d;4px):noGrow,left:4dlu:noGrow,fill:d:grow", "center:d:noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow"));
        southLeftPanel.add(passiveDetailPanel, BorderLayout.CENTER);
        sensitivePathPanel = new JPanel();
        sensitivePathPanel.setLayout(new BorderLayout(0, 0));
        passiveDetailPanel.add(sensitivePathPanel, cc.xy(3, 1, CellConstraints.LEFT, CellConstraints.DEFAULT));
        sensitiveCheckBox = new JCheckBox();
        sensitiveCheckBox.setSelected(true);
        sensitiveCheckBox.setText("??????????????????");
        sensitivePathPanel.add(sensitiveCheckBox, BorderLayout.WEST);
        sensitiveHelp = new JLabel();
        sensitiveHelp.setForeground(new Color(-65536));
        sensitiveHelp.setText("???????????????????????????????????????????????????");
        sensitivePathPanel.add(sensitiveHelp, BorderLayout.CENTER);
        fingerPanel = new JPanel();
        fingerPanel.setLayout(new BorderLayout(0, 0));
        passiveDetailPanel.add(fingerPanel, cc.xy(3, 3, CellConstraints.LEFT, CellConstraints.DEFAULT));
        fingerCheckBox = new JCheckBox();
        fingerCheckBox.setSelected(true);
        fingerCheckBox.setText("????????????");
        fingerPanel.add(fingerCheckBox, BorderLayout.WEST);
        fingerHelp = new JLabel();
        fingerHelp.setForeground(new Color(-65536));
        fingerHelp.setText("????????????????????????????????????");
        fingerPanel.add(fingerHelp, BorderLayout.CENTER);
        languagePanel = new JPanel();
        languagePanel.setLayout(new BorderLayout(0, 0));
        passiveDetailPanel.add(languagePanel, cc.xy(3, 5, CellConstraints.LEFT, CellConstraints.DEFAULT));
        languageCheckBox = new JCheckBox();
        languageCheckBox.setSelected(true);
        languageCheckBox.setText("??????????????????");
        languagePanel.add(languageCheckBox, BorderLayout.WEST);
        languageHelp = new JLabel();
        languageHelp.setForeground(new Color(-65536));
        languageHelp.setText("???????????????????????????????????????????????????");
        languagePanel.add(languageHelp, BorderLayout.CENTER);
        infoLeakPanel = new JPanel();
        infoLeakPanel.setLayout(new BorderLayout(0, 0));
        infoLeakPanel.setForeground(new Color(-65536));
        passiveDetailPanel.add(infoLeakPanel, cc.xy(3, 7, CellConstraints.LEFT, CellConstraints.DEFAULT));
        infoLeakCheckBox = new JCheckBox();
        infoLeakCheckBox.setSelected(true);
        infoLeakCheckBox.setText("??????????????????");
        infoLeakPanel.add(infoLeakCheckBox, BorderLayout.WEST);
        infoLeakHelp = new JLabel();
        infoLeakHelp.setForeground(new Color(-65536));
        infoLeakHelp.setText("????????????????????????????????????????????????root:xx");
        infoLeakPanel.add(infoLeakHelp, BorderLayout.CENTER);
        listDirectoryPanel = new JPanel();
        listDirectoryPanel.setLayout(new BorderLayout(0, 0));
        listDirectoryPanel.setForeground(new Color(-65536));
        passiveDetailPanel.add(listDirectoryPanel, cc.xy(3, 9, CellConstraints.LEFT, CellConstraints.DEFAULT));
        listDirectoryCheckBox = new JCheckBox();
        listDirectoryCheckBox.setSelected(true);
        listDirectoryCheckBox.setText("???????????????");
        listDirectoryPanel.add(listDirectoryCheckBox, BorderLayout.WEST);
        listDirectoryHelp = new JLabel();
        listDirectoryHelp.setForeground(new Color(-65536));
        listDirectoryHelp.setText("??????index of /????????????????????????????????????");
        listDirectoryPanel.add(listDirectoryHelp, BorderLayout.CENTER);
        SSRFPanel = new JPanel();
        SSRFPanel.setLayout(new BorderLayout(0, 0));
        passiveDetailPanel.add(SSRFPanel, cc.xy(3, 11, CellConstraints.LEFT, CellConstraints.DEFAULT));
        SSRFCheckBox = new JCheckBox();
        SSRFCheckBox.setText("SSRF??????");
        SSRFPanel.add(SSRFCheckBox, BorderLayout.WEST);
        SSRFHelp = new JLabel();
        SSRFHelp.setForeground(new Color(-65536));
        SSRFHelp.setText("??????????????????????????????url????????????");
        SSRFPanel.add(SSRFHelp, BorderLayout.CENTER);
        wafPanel = new JPanel();
        wafPanel.setLayout(new BorderLayout(0, 0));
        passiveDetailPanel.add(wafPanel, cc.xy(3, 13, CellConstraints.LEFT, CellConstraints.DEFAULT));
        wafCheckBox = new JCheckBox();
        wafCheckBox.setText("WAF?????????????????????");
        wafPanel.add(wafCheckBox, BorderLayout.WEST);
        wafHelp = new JLabel();
        wafHelp.setForeground(new Color(-65536));
        wafHelp.setText("??????????????????????????????WAF");
        wafPanel.add(wafHelp, BorderLayout.CENTER);
        final Spacer spacer3 = new Spacer();
        passiveDetailPanel.add(spacer3, cc.xy(1, 1, CellConstraints.DEFAULT, CellConstraints.FILL));
        southRightPanel = new JPanel();
        southRightPanel.setLayout(new BorderLayout(0, 0));
        southSpiltPanel.setRightComponent(southRightPanel);
        southRightPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        activeAllPanel = new JPanel();
        activeAllPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        southRightPanel.add(activeAllPanel, BorderLayout.NORTH);
        activeAllPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        activeAllCheckBox = new JCheckBox();
        activeAllCheckBox.setSelected(true);
        activeAllCheckBox.setText("??????????????????");
        activeAllPanel.add(activeAllCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        activePanelHelp = new JLabel();
        activePanelHelp.setForeground(new Color(-65536));
        activePanelHelp.setText("   ???????????????????????????????????????????????????????????????");
        activeAllPanel.add(activePanelHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        activeDetailPanel = new JPanel();
        activeDetailPanel.setLayout(new FormLayout("fill:max(d;4px):noGrow,left:4dlu:noGrow,fill:d:grow", "center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow,top:3dlu:noGrow,center:max(d;4px):noGrow"));
        southRightPanel.add(activeDetailPanel, BorderLayout.CENTER);
        exceptionParaPanel = new JPanel();
        exceptionParaPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(exceptionParaPanel, cc.xy(3, 1, CellConstraints.LEFT, CellConstraints.DEFAULT));
        exceptionParaCheckBox = new JCheckBox();
        exceptionParaCheckBox.setText("?????????????????????????????????");
        exceptionParaPanel.add(exceptionParaCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        exceptionParaHelp = new JLabel();
        exceptionParaHelp.setForeground(new Color(-65536));
        exceptionParaHelp.setText("???????????????????????????????????????????????????????????????????????????");
        exceptionParaPanel.add(exceptionParaHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        backupFilePanel = new JPanel();
        backupFilePanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(backupFilePanel, cc.xy(3, 9, CellConstraints.LEFT, CellConstraints.DEFAULT));
        backupFileCheckBox = new JCheckBox();
        backupFileCheckBox.setText("?????????????????????????????????");
        backupFilePanel.add(backupFileCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        backupFileHelp = new JLabel();
        backupFileHelp.setForeground(new Color(-65536));
        backupFileHelp.setText("???????????????????????????????????????");
        backupFilePanel.add(backupFileHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        infoFilePanel = new JPanel();
        infoFilePanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(infoFilePanel, cc.xy(3, 11, CellConstraints.LEFT, CellConstraints.DEFAULT));
        infoFileCheckBox = new JCheckBox();
        infoFileCheckBox.setText("?????????????????????????????????");
        infoFilePanel.add(infoFileCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        infoFileHelp = new JLabel();
        infoFileHelp.setForeground(new Color(-65536));
        infoFileHelp.setText("???????????????????????????????????????");
        infoFilePanel.add(infoFileHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        activeFingerPanel = new JPanel();
        activeFingerPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(activeFingerPanel, cc.xy(3, 13, CellConstraints.LEFT, CellConstraints.DEFAULT));
        activeFingerCheckBox = new JCheckBox();
        activeFingerCheckBox.setText("?????????????????????????????????");
        activeFingerPanel.add(activeFingerCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        activeFingerHelp = new JLabel();
        activeFingerHelp.setForeground(new Color(-65536));
        activeFingerHelp.setText("???????????????????????????????????????");
        activeFingerPanel.add(activeFingerHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        knownFingerDirScanPanel = new JPanel();
        knownFingerDirScanPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(knownFingerDirScanPanel, cc.xy(3, 15, CellConstraints.LEFT, CellConstraints.DEFAULT));
        knownFingerDirScanCheckBox = new JCheckBox();
        knownFingerDirScanCheckBox.setText("??????????????????????????????");
        knownFingerDirScanPanel.add(knownFingerDirScanCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        knownFingerDirScanHelp = new JLabel();
        knownFingerDirScanHelp.setForeground(new Color(-65536));
        knownFingerDirScanHelp.setText("?????????????????????????????????????????????????????????????????????");
        knownFingerDirScanPanel.add(knownFingerDirScanHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        unexistsPathPanel = new JPanel();
        unexistsPathPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(unexistsPathPanel, cc.xy(3, 3, CellConstraints.LEFT, CellConstraints.DEFAULT));
        unexistsPathCheckBox = new JCheckBox();
        unexistsPathCheckBox.setSelected(true);
        unexistsPathCheckBox.setText("????????????????????????");
        unexistsPathPanel.add(unexistsPathCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        unexistsPathHelp = new JLabel();
        unexistsPathHelp.setForeground(new Color(-65536));
        unexistsPathHelp.setText("?????????????????????????????????????????????????????????????????????");
        unexistsPathPanel.add(unexistsPathHelp, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        activeListDirectoryPanel = new JPanel();
        activeListDirectoryPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(activeListDirectoryPanel, cc.xy(3, 5, CellConstraints.LEFT, CellConstraints.DEFAULT));
        activeListDirectoryCheckBox = new JCheckBox();
        activeListDirectoryCheckBox.setText("?????????????????????");
        activeListDirectoryPanel.add(activeListDirectoryCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        activeListDirectoryLabel = new JLabel();
        activeListDirectoryLabel.setForeground(new Color(-65536));
        activeListDirectoryLabel.setText("????????????????????????????????????????????????3??????????????????????????????????????????");
        activeListDirectoryPanel.add(activeListDirectoryLabel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        activeJsonErrorTestPanel = new JPanel();
        activeJsonErrorTestPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), 2, 0));
        activeDetailPanel.add(activeJsonErrorTestPanel, cc.xy(3, 7, CellConstraints.LEFT, CellConstraints.DEFAULT));
        activeJsonErrorTestCheckBox = new JCheckBox();
        activeJsonErrorTestCheckBox.setSelected(true);
        activeJsonErrorTestCheckBox.setText("json????????????");
        activeJsonErrorTestPanel.add(activeJsonErrorTestCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        activeJsonErrorTestLabel = new JLabel();
        activeJsonErrorTestLabel.setForeground(new Color(-65536));
        activeJsonErrorTestLabel.setText("?????????????????????json????????????????????????????????????");
        activeJsonErrorTestPanel.add(activeJsonErrorTestLabel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    public void dirHeaderAction(boolean status){
        dirHeaderScrollPane.setEnabled(status);
        dirHeaderTextArea.setEnabled(status);
        dirHeaderTextArea.setEditable(status);
        dirHeaderAddButton.setEnabled(status);
        dirHeaderRecoverButton.setEnabled(status);
        dirHeaderWrap.setEnabled(status);
    }

    public void userAgentAction(boolean status){
        chromeRadioButton.setEnabled(status);
        firefoxRadioButton.setEnabled(status);
        IE7RadioButton.setEnabled(status);
        iphoneRadioButton.setEnabled(status);
    }

    public void changeTips(boolean status){
        backupChangeTips.setVisible(status);
        fingerChangeTips.setVisible(status);
        infoChangeTips.setVisible(status);
        pocChangeTips.setVisible(status);
    }

    public JCheckBox getActiveListDirectoryCheckBox() {
        return activeListDirectoryCheckBox;
    }

    public JCheckBox getActiveJsonErrorTestCheckBox() {
        return activeJsonErrorTestCheckBox;
    }

    public JCheckBox getKnownFingerDirScanCheckBox() {
        return knownFingerDirScanCheckBox;
    }

    public JCheckBox getLanguageCheckBox() {
        return languageCheckBox;
    }

    public JTextArea getDirHeaderTextArea() {
        return dirHeaderTextArea;
    }

    public JCheckBox getDirHeaderCheckBox() {
        return dirHeaderCheckBox;
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    public JTextField getPocPathTextField() {
        return pocPathTextField;
    }

    public JTextField getBackupPathTextField() {
        return backupPathTextField;
    }

    public JCheckBox getAddRememberMeButton() {
        return addRememberMeButton;
    }

    public JCheckBox getResponseBeautyCheckBox() {
        return responseBeautyCheckBox;
    }

    public JTextField getBrowserPathTextField() {
        return browserPathTextField;
    }

    public JCheckBox getSSRFCheckBox() {
        return SSRFCheckBox;
    }

    public JCheckBox getListDirectoryCheckBox() {
        return listDirectoryCheckBox;
    }

    public JCheckBox getUnexistsPathCheckBox() {
        return unexistsPathCheckBox;
    }

    public JTextField getFingerPathTextField() {
        return fingerPathTextField;
    }

    public JTextField getInfoPathTextField() {
        return infoPathTextField;
    }

    public JCheckBox getInfoFileCheckBox() {
        return infoFileCheckBox;
    }

    public JCheckBox getStatusTo200CheckBox() {
        return statusTo200CheckBox;
    }

    public JCheckBox getFlushBrowserCheckBox() {
        return flushBrowserCheckBox;
    }

    public JCheckBox getFingerCheckBox() {
        return fingerCheckBox;
    }

    public JLabel getStatus() {
        return Status;
    }

    private void setGlobalSetting(boolean status){
        // ?????????true?????????????????????????????????????????????????????????????????????????????????????????????false???????????????????????????????????????false
        if(status==false){
            addRememberMeButton.setSelected(status);
            flushBrowserCheckBox.setSelected(status);
            wechatFakeCheckBox.setSelected(status);
            statusTo200CheckBox.setSelected(status);
            responseBeautyCheckBox.setSelected(status);
            chunkedBox.setSelected(status);
            dirHeaderCheckBox.setSelected(status);
            dirHeaderAction(status);
            userAgentAction(status);
        }
        addRememberMeButton.setEnabled(status);
        flushBrowserCheckBox.setEnabled(status);
        wechatFakeCheckBox.setEnabled(status);
        statusTo200CheckBox.setEnabled(status);
        responseBeautyCheckBox.setEnabled(status);
        browserPathTextField.setEnabled(status);
        fingerPathTextField.setEnabled(status);
        infoPathTextField.setEnabled(status);
        activeProxyComboBox.setEnabled(status);
        reloadConfigButton.setEnabled(status);
        activeProxyTextField.setEnabled(status);
        chunkedBox.setEnabled(status);
        dirHeaderCheckBox.setEnabled(status);
        disableJSCheckBox.setEnabled(status);
        dirHeaderAddButton.setEnabled(status);
        dirHeaderRecoverButton.setEnabled(status);
        dirHeaderWrap.setEnabled(status);
    }

    private void setActiveSetting(boolean status){
        if(status==false){
            unexistsPathCheckBox.setSelected(status);
            backupFileCheckBox.setSelected(status);
            infoFileCheckBox.setSelected(status);
            exceptionParaCheckBox.setSelected(status);
            activeFingerCheckBox.setSelected(status);
            knownFingerDirScanCheckBox.setSelected(status);
            activeListDirectoryCheckBox.setSelected(status);
            activeJsonErrorTestCheckBox.setSelected(status);
        }
        unexistsPathCheckBox.setEnabled(status);
        backupFileCheckBox.setEnabled(status);
        infoFileCheckBox.setEnabled(status);
        exceptionParaCheckBox.setEnabled(status);
        activeFingerCheckBox.setEnabled(status);
        knownFingerDirScanCheckBox.setEnabled(status);
        activeListDirectoryCheckBox.setEnabled(status);
        activeJsonErrorTestCheckBox.setEnabled(status);
    }

    private void setPassiveSetting(boolean status){
        if(status==false){
            SSRFCheckBox.setSelected(status);
            listDirectoryCheckBox.setSelected(status);
            infoLeakCheckBox.setSelected(status);
            fingerCheckBox.setSelected(status);
            wafCheckBox.setSelected(status);
            languageCheckBox.setSelected(status);
            sensitiveCheckBox.setSelected(status);
        }
        SSRFCheckBox.setEnabled(status);
        listDirectoryCheckBox.setEnabled(status);
        infoLeakCheckBox.setEnabled(status);
        fingerCheckBox.setEnabled(status);
        wafCheckBox.setEnabled(status);
        languageCheckBox.setEnabled(status);
        sensitiveCheckBox.setEnabled(status);
    }

    public JCheckBox getInfoLeakCheckBox() {
        return infoLeakCheckBox;
    }

    public JCheckBox getSensitiveCheckBox() {
        return sensitiveCheckBox;
    }

    public JRadioButton getDirHeaderAddButton() {
        return dirHeaderAddButton;
    }

    public JCheckBox getUserAgentCheckBox() {
        return userAgentCheckBox;
    }

    public JRadioButton getChromeRadioButton() {
        return chromeRadioButton;
    }

    public JRadioButton getIphoneRadioButton() {
        return iphoneRadioButton;
    }

    public JRadioButton getIE7RadioButton() {
        return IE7RadioButton;
    }

    public JRadioButton getFirefoxRadioButton() {
        return firefoxRadioButton;
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }

}

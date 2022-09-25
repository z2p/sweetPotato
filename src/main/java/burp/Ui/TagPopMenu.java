package burp.Ui;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class TagPopMenu {

    private JPopupMenu menu;
    private JMenuItem titleMenu;
    private JMenuItem knownFingerDirScan;
    private JMenuItem backupFileScan;
    private JMenu pocScan;

    public TagPopMenu(){
        menu = new JPopupMenu();
        titleMenu = new JMenuItem();
        titleMenu.setEnabled(false);
        knownFingerDirScan = new JMenuItem("已知组件的目录扫描");
        backupFileScan = new JMenuItem("备份文件扫描");
        pocScan = new JMenu("漏洞探测");
        menu.add(titleMenu);
        menu.add(knownFingerDirScan);
        menu.add(backupFileScan);
        menu.add(pocScan);

        // 已知组件的目录扫描
//        knownFingerDirScan.addActionListener(new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent e) {
//
//            }
//        });
//
//        // 备份文件扫描
//        backupFile.addActionListener(new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent e) {
//
//            }
//        });
    }



    public JMenuItem getTitleMenu() {
        return titleMenu;
    }

    public JPopupMenu getMenu() {
        return menu;
    }

    public JMenuItem getKnownFingerDirScan() {
        return knownFingerDirScan;
    }

    public void setKnownFingerDirScanTextToDefault(){
        knownFingerDirScan.setText("已知组件的目录扫描");
    }

    public JMenuItem getBackupFileScan() {
        return backupFileScan;
    }
}

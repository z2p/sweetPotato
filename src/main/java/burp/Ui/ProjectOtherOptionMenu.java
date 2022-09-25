package burp.Ui;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ProjectOtherOptionMenu {

    private JPopupMenu menu;
    private JMenuItem setTargetItem;
    private JMenuItem freshTitleItem;
    private JMenuItem importItem;
    private JMenuItem exportItem;
    private JMenuItem globalSearchItem;
    private JMenuItem copySelectItem;

    public ProjectOtherOptionMenu(){
        menu = new JPopupMenu();
        setTargetItem = new JMenuItem("目标管理");
        freshTitleItem = new JMenuItem("刷新标题");
        importItem = new JMenuItem("导入");
        exportItem = new JMenuItem("导出");
        globalSearchItem = new JMenuItem("全局搜索");
        copySelectItem = new JMenuItem("批量复制");

        menu.add(setTargetItem);
        menu.add(freshTitleItem);
        menu.add(importItem);
        menu.add(exportItem);
        menu.add(globalSearchItem);
        menu.add(copySelectItem);
    }

    public JMenuItem getCopySelectItem() {
        return copySelectItem;
    }

    public JMenuItem getSetTargetItem() {
        return setTargetItem;
    }

    public JMenuItem getGlobalSearchItem() {
        return globalSearchItem;
    }

    public JMenuItem getFreshTitleItem() {
        return freshTitleItem;
    }

    public JMenuItem getImportItem() {
        return importItem;
    }

    public JMenuItem getExportItem() {
        return exportItem;
    }

    public JPopupMenu getMenu() {
        return menu;
    }
}

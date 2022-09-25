package burp.Bootstrap;

import burp.Controller.DirScanThread;
import burp.Ui.Main2Tag;
import burp.Ui.TagPopMenu;
import com.alibaba.fastjson.JSONArray;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.Map;

public class URLTableClass extends JTable {

    public static int focusedRowIndex = -1;
    public ArrayList<String> columnNames;
    public TagPopMenu tagPopMenu;
    // 默认是开启右键监听器的
    public boolean disableRigthMouseAction = false;
    private Config config;

    public URLTableClass(TableModel tableModel,Config config) {
        super(tableModel);
        this.config = config;
        this.columnNames = new ArrayList<String>();
        this.tagPopMenu = new TagPopMenu();

        // 头部标题美化
        JTableHeader jTableHeader = this.getTableHeader();
        jTableHeader.setBackground(new Color(251, 251, 251));
        // 所有列都居中
        DefaultTableCellRenderer render = new DefaultTableCellRenderer() {
            public Component getTableCellRendererComponent(JTable table, Object value,boolean isSelected, boolean hasFocus, int row, int column) {
                Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                // TODO: 这里后面要改一下
                if(table.getColumnName(column).equals("finger")) {
                    cell.setForeground(new Color(9,109,217));
                }
                else if(table.getValueAt(row,column).toString().equals("Exception")){
                    cell.setForeground(new Color(252, 25, 68));
                }
                else{
                    cell.setForeground(new Color(0,0,0));
                }

                if(isSelected){
                    cell.setBackground(new Color(255, 197, 153));
                }
                else{
                    if(row % 2 == 0){
                        cell.setBackground(new Color(255,255,255));
                    }
                    else{
                        cell.setBackground(new Color(242,242,242));
                    }
                }

                return cell;
            }
        };
        render.setHorizontalAlignment(SwingConstants.CENTER);
        int columnCount = this.getColumnCount();
        for(int i=0;i<columnCount;i++){
            this.getColumn(this.getColumnName(i)).setCellRenderer(render);
            columnNames.add(this.getColumnName(i));
        }
        // 特殊字段固定长度
        this.getColumn("#").setMinWidth(40);
        this.getColumn("#").setMaxWidth(40);
        this.getColumn("time").setMinWidth(150);
        this.getColumn("time").setMaxWidth(150);
        this.getColumn("length").setWidth(80);
        this.getColumn("length").setMaxWidth(80);
        this.getColumn("status").setWidth(80);
        this.getColumn("status").setMaxWidth(80);

        // 定义右键监听器
        this.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // 左键双击使用浏览器打开
                if(e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    tableLeftDoubleClickAction(e,config.getTags().getMain2Tag());
                }
                // 右键弹出菜单
                if(SwingUtilities.isRightMouseButton(e) && disableRigthMouseAction == false){
                    tableRightClickAction(e, tagPopMenu);
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

        // 定义tagPopMenu点击后的监听器
//        this.tagPopMenuAddListener();
    }

    public void tableLeftDoubleClickAction(MouseEvent e, Main2Tag main2Tag){
        int row = getSelectedRow();
        String url = this.getValueAt(row,1).toString();
        try{
            Tools.openBrowser(url, main2Tag.getBrowserPathTextField().getText());
        } catch(Exception e1){
            e1.printStackTrace();
        }
    }

    public void setDisableRigthMouseAction(boolean disableRigthMouseAction) {
        this.disableRigthMouseAction = disableRigthMouseAction;
    }

    public void tableRightClickAction(MouseEvent e, TagPopMenu tagPopMenu){
        setFocusedRowIndex(rowAtPoint(e.getPoint()));
        if(this.getFocusedRowIndex() == -1){
            return;
        }
        // 修改聚焦的函数
        setRowSelectionInterval(getFocusedRowIndex(),getFocusedRowIndex());
        // 获取一些信息进行展示
        String host = getValueAt(getFocusedRowIndex(),1).toString();
        tagPopMenu.getTitleMenu().setText(host);
        // 如果没finger字段，已知组件的目录扫描，就不开放
        if(columnNames.contains("finger")){
            String finger = getValueAt(getFocusedRowIndex(),4).toString();
            int sensitivePathCount = Tools.getFingerSensitivePathCount(config.getFingerJsonInfo(),finger);
            tagPopMenu.getKnownFingerDirScan().setText("已知组件的目录扫描（"+ finger + "） 字典数量：" + sensitivePathCount);
            tagPopMenu.getKnownFingerDirScan().setEnabled(sensitivePathCount != 0);
        }
        else{
            tagPopMenu.getKnownFingerDirScan().setEnabled(false);
            tagPopMenu.setKnownFingerDirScanTextToDefault();
        }

        tagPopMenu.getMenu().show(this,e.getX(),e.getY());

    }

    /**
     * 为表格的tagpopmenu增加监听器
     */
    public void tagPopMenuAddListener(){
        // 当用户点击了【已知组件的目录扫描】
        tagPopMenu.getKnownFingerDirScan().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 1. 取出当前所在的行数
                // 2. 拿出当前行数的信息，给到目录扫描的逻辑
                String host = CustomBurpUrl.getRequestDomainName(getValueAt(focusedRowIndex,1).toString());
                String finger = getValueAt(focusedRowIndex,4).toString();
                String type = "已识别组件扫描";
                // 3. 给到目录扫描的模块
                // 3.1 组装好所有需要扫描的url地址
                ArrayList<String> scanUrls = new ArrayList<>();
                for (Map.Entry<String,Object> info:config.getFingerJsonInfo().getJSONObject(finger).getJSONObject("SensitivePath").entrySet()){
                    scanUrls.add(host+info.getKey());
                }
                DirScanThread dirScanThread = new DirScanThread(scanUrls,config.getTags(),config,type);
                Thread t = new Thread(dirScanThread);
                t.start();
            }
        });

        // 当用户点击了【备份文件扫描】
        tagPopMenu.getBackupFileScan().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String host = CustomBurpUrl.getRequestDomainName(getValueAt(focusedRowIndex,1).toString());
                String type = "备份文件扫描";
                ArrayList<String> scanUrls = new ArrayList<>();
                JSONArray paths = config.getBackupFileJsonInfo().getJSONArray("package");
                for(int i=0;i<paths.size();i++){
                    String path = paths.getString(i);
                    if(path.contains("%domain%")){
                        path = path.replace("%domain%",CustomBurpUrl.getDomain(host));
                    }
                    scanUrls.add(host+path);
                }
                DirScanThread dirScanThread = new DirScanThread(scanUrls,config.getTags(),config,type);
                Thread t = new Thread(dirScanThread);
                t.start();
            }
        });
    }

    public int getFocusedRowIndex() {
        return focusedRowIndex;
    }

    public void setFocusedRowIndex(int focusedRowIndex) {
        this.focusedRowIndex = focusedRowIndex;
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        super.changeSelection(rowIndex, columnIndex, toggle, extend);
    }
}

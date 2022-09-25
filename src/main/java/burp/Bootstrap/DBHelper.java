package burp.Bootstrap;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.Ui.ProjectTableTag;
import com.alibaba.fastjson.JSONObject;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.Set;
import java.util.stream.Collectors;

public class DBHelper {

    private String dbFilePath;
    private Connection conn;

    public DBHelper(String dbFilePath){

        this.dbFilePath = dbFilePath;
        try{
            Class.forName("org.sqlite.JDBC");
            conn = DriverManager.getConnection(String.format("jdbc:sqlite:%s",dbFilePath));
            conn.setAutoCommit(true);
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void connectionClose(Connection conn){
        if(conn == null) return;
        try{
            conn.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }


    public void statmentClose(Statement statement){
        if(statement == null) return;
        try{
            statement.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    public void resultSetClose(ResultSet resultSet){
        try{
            resultSet.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * 当用户打开的是一个全新的文件时候，那就要对表的结构做一定的初始化
     */
    public void initCreateTable(){

        Statement statement = null;
        try{
            statement = conn.createStatement();
            // 创建表
            String createTargetSQL = "create table targets(id INTEGER,name text primary key not null)"; // 存放用户下发的目标
            String createURLSQL = "create table url(id INTEGER,url text primary key,content text not null)";   // 存放url的目标
            statement.executeUpdate(createTargetSQL);
            statement.executeUpdate(createURLSQL);

        } catch (Exception e){
            e.printStackTrace();
        } finally{
            statmentClose(statement);
        }
    }

    /**
     * 将数据写入到url表里
     */
    public boolean insertToUrlTable(HTTPResponse httpResponse,IHttpRequestResponse messageInfo,int id,String time){

        boolean isSeccess = false;
        String finger = httpResponse.getFingers().stream().map(integer -> integer.toString()).collect(Collectors.joining(","));

        String sql = "insert into url (id,url,content) values('%d','%s','%s')";
        String content = "{\"domain\":\"%s\",\"status\":\"%d\",\"length\":\"%d\",\"title\":\"%s\",\"server\":\"%s\",\"finger\":\"%s\",\"isCheck\":\"%s\",\"assetType\":\"%s\",\"comments\":\"%s\",\"ip\":\"%s\",\"updateTime\":\"%s\",\"request\":\"%s\",\"response\":\"%s\"}";
        content = String.format(
                content,
                httpResponse.getDomain(),
                httpResponse.getStatus(),
                httpResponse.getLength(),
                Base64.getEncoder().encodeToString(httpResponse.getTitle().getBytes(StandardCharsets.UTF_8)),
                Base64.getEncoder().encodeToString(httpResponse.getServer().getBytes(StandardCharsets.UTF_8)),
                finger,
                httpResponse.getIsCheck(),
                httpResponse.getAssetType(),
                Base64.getEncoder().encodeToString(httpResponse.getComments().getBytes(StandardCharsets.UTF_8)),
                httpResponse.getIp(),
                time,
                Base64.getEncoder().encodeToString(messageInfo.getRequest()),
                Base64.getEncoder().encodeToString(messageInfo.getResponse())
        );
        sql = String.format(sql,id,httpResponse.getHost(),content);
        Statement statement = null;
        try{
            statement = conn.createStatement();
            statement.executeUpdate(sql);
            isSeccess = true;
        } catch (Exception e){
            e.printStackTrace();
            isSeccess = false;
        } finally {
            statmentClose(statement);
        }
        return isSeccess;
    }

    /**
     * 当用户更新了comment的内容，写库
     */
    public void updateUrlTable(String url,String keyName,String keyValue){

        String sql = "select * from url where url='%s'";
        Statement statement = null;
        ResultSet resultSet = null;
        try{
            statement = conn.createStatement();
            resultSet = statement.executeQuery(String.format(sql,url));
            while(resultSet.next()){
                String content = resultSet.getString("content");
                JSONObject json = JSONObject.parseObject(content);
                // 更改
                json.put(keyName,keyValue);
                // 将json转成str
                String newContent = json.toString();
                // 更新数据库
                statement.executeUpdate(String.format("update url set content='%s' where url='%s'",newContent,url));
            }
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            statmentClose(statement);
            resultSetClose(resultSet);
        }
    }

    public void insertToTargetTable(int id,String domain){

        String sql = "insert into targets(id,name) values('%s','%s')";
        sql = String.format(sql,id,domain);
        Statement statement = null;

        try{
            statement = conn.createStatement();
            statement.executeUpdate(sql);
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            statmentClose(statement);
        }
    }

    /**
     * 目标管理表
     */
    public void getInfoFromTargetTable(DefaultListModel dlm, Set<String> targetHashSet) throws Exception{

        String sql = "select * from targets order by id";
        Statement statement = conn.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        while(resultSet.next()){
            String name = resultSet.getString("name");
            dlm.addElement(name);
            targetHashSet.add(name);
        }
        statmentClose(statement);
        resultSetClose(resultSet);
    }

    /**
     * url表里的数据管理
     */
    public void getInfoFromUrlTable(Set<String> urlHashSet, Set<String> ipRecord,ProjectTableTag projectTableTag) throws Exception{

        String sql = "select * from url order by id";
        Statement statement = conn.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        while(resultSet.next()) {
            int id = resultSet.getInt("id");
            String url = resultSet.getString("url");
            String content = resultSet.getString("content");

            JSONObject json = JSONObject.parseObject(content);
            urlHashSet.add(url);
            // 判断一下，哪一些是IP，要录入到iprecord里的
            if(Tools.isIP(json.getString("domain"))){
                ipRecord.add(url);
            }

            IHttpRequestResponse messageInfo = new IHttpRequestResponse() {
                @Override
                public byte[] getRequest() {
                    return Base64.getDecoder().decode(json.getString("request"));
                }

                @Override
                public void setRequest(byte[] message) {

                }

                @Override
                public byte[] getResponse() {
                    return Base64.getDecoder().decode(json.getString("response"));
                }

                @Override
                public void setResponse(byte[] message) {

                }

                @Override
                public String getComment() {
                    return null;
                }

                @Override
                public void setComment(String comment) {

                }

                @Override
                public String getHighlight() {
                    return null;
                }

                @Override
                public void setHighlight(String color) {

                }

                @Override
                public IHttpService getHttpService() {
                    return null;
                }

                @Override
                public void setHttpService(IHttpService httpService) {

                }
            };
            projectTableTag.add(
                    url,
                    json.getString("domain"),
                    json.getInteger("status"),
                    json.getInteger("length"),
                    new String(Base64.getDecoder().decode(json.getString("title"))),
                    new String(Base64.getDecoder().decode(json.getString("server"))),
                    json.getString("finger"),
                    json.getString("isCheck"),
                    json.getString("assetType"),
                    new String(Base64.getDecoder().decode(json.getString("comments"))),
                    json.getString("ip"),
                    json.getString("updateTime"),
                    messageInfo
            );
        }

        statmentClose(statement);
        resultSetClose(resultSet);
    }

    public Connection getConn() {
        return conn;
    }
}

package burp.Controller;

import burp.*;
import burp.Bootstrap.*;
import burp.Ui.ProjectTableTag;
import burp.Ui.Tags;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VulnsController {

    public VulnsController(){

    }

    /**
     * 主动扫描模块
     * @param httpResponse
     * @param tags
     */
    public void activeScanController(HTTPRequests httpRequests, HTTPResponse httpResponse, Tags tags, Config config){

        Set<String> activeScanRecord = config.getActiveScanRecord();
        IExtensionHelpers helpers = config.getHelpers();
        IBurpExtenderCallbacks callbacks = config.getCallbacks();

        // 不存在的路径访问，并且将结果给到各个被动引擎进行分析；如果这个key已经在字典里，说明这个目标已经进行过这一项的扫描了，可以不需要扫描，这里的流量都会走被动
        String key = httpResponse.getHost() + "unExistsPathScan";
        if(tags.getMain2Tag().getUnexistsPathCheckBox().isSelected() && !activeScanRecord.contains(key)){
            try{
                String scanUrl = httpResponse.getHost() + "/askdjkiuczxvio123asdas.html";
                // 获取之前访问的头部字段信息
                List<String> requestsHeaders = helpers.analyzeRequest(httpRequests.getByteRequestsRaw()).getHeaders();
                // remove移除请求行和host
                requestsHeaders.remove(0);
                requestsHeaders.remove(0);

                IHttpRequestResponse messageInfo = BurpSuiteRequests.get(scanUrl,requestsHeaders,callbacks,false,config,5);
                // 获取新的对象
                HTTPRequests newHttpRequest = new HTTPRequests(callbacks,messageInfo);
                HTTPResponse newHttpResponse = new HTTPResponse(callbacks,messageInfo);

                // 将流量给到被动分析的所有引擎
                passiveScanController(newHttpRequest,newHttpResponse,messageInfo,tags,config);

                // 更新被动的指纹到主动的对象里，采用追加和去重的方式操作
                httpResponse.setFingers(Tools.arrayListAddArrayList(httpResponse.getFingers(),newHttpResponse.getFingers()));

            } catch (Exception e){
                e.printStackTrace();;
            } finally {
                activeScanRecord.add(key);
            }
        }

        // 已识别组件的目录扫描，调用了dirScanThread 这个对象会自动将流量都走被动
        key = httpResponse.getHost() + "knownFingerDirScan";
        if(tags.getMain2Tag().getKnownFingerDirScanCheckBox().isSelected() && !activeScanRecord.contains(key)){
            System.out.println("正在对 " + httpResponse.getHost() + " 进行已识别的目录扫描");
            try{
                String type = "已识别组件扫描";
                DirScanThread dirScanThread = new DirScanThread(httpResponse.getHost(), httpResponse.getFingers(), tags,config,type);
                Thread t = new Thread(dirScanThread);
                t.start();
            } catch (Exception e){
                e.printStackTrace();
            } finally {
                activeScanRecord.add(key);
            }
        }

        // 主动列目录，已识别的组件就不做列目录扫描了
        key = httpResponse.getHost() + "ActiveListDirectoryScan";
        if(tags.getMain2Tag().getActiveListDirectoryCheckBox().isSelected() && !activeScanRecord.contains(key) && httpResponse.getFingers().size() == 0){
//            System.out.println("正在对 " + httpResponse.getHost() + " 进行主动列目录的识别");
            // 创建要扫描的字典
            ArrayList<String> scanUrls = new ArrayList<String>();
            String type = "主动列目录扫描";
            boolean isScan = false;
            // 1、获取httpResponse里的currentLinkDirectory
            HashSet<String> currentLinkDirectory = httpResponse.getCurrentLinkDirectory();
            // 2、转化成list
            ArrayList<String> paths = new ArrayList<String>(currentLinkDirectory);
            ArrayList<String> newPaths = new ArrayList<String>();
            // 3、如果currentLinkDirectory里的数量少于2个，则不进行探测，也不更新扫描记录；等待下一次遇到大于等于2个的目标，进行探测
            // 4、最多进行3个目录的探测
            if(paths.size() == 2){
                newPaths.add(paths.get(0));
                newPaths.add(paths.get(1));
                isScan = true;
            }
            else if(paths.size() > 2){
                newPaths.add(paths.get(0));
                newPaths.add(paths.get(1));
                newPaths.add(paths.get(2));
                isScan = true;
            }
            if(isScan){
                // 5、拼接 host + currentPath + LinkDirectory
                for(int i=0;i< newPaths.size();i++){
                    String scanUrl = httpResponse.getHost() + httpResponse.getCurrentPath().substring(0,httpResponse.getCurrentPath().length()-1) + newPaths.get(i);
//                    System.out.println("正在对 " + scanUrl + "进行主动列目录识别");
                    scanUrls.add(scanUrl);
                }
                // 6、给到dirScanThread
                DirScanThread dirScanThread = new DirScanThread(scanUrls,tags,config,type);
                Thread t = new Thread(dirScanThread);
                t.start();
                // 7、扫描记录更新
                activeScanRecord.add(key);
            }
        }

        // json测试
        key = httpResponse.getHost() + "JSONErrorTest";
        // 如果按钮被选择 并且 （（编程语言是jsp 或者 是unknown）并且 请求contenttype是json） 并且 没被扫描过
        if(tags.getMain2Tag().getActiveJsonErrorTestCheckBox().isSelected() && ((httpResponse.getLanguage().equals("JSP") || httpResponse.getLanguage().equals("unknown")) && httpRequests.getContentType() == 4) && !activeScanRecord.contains(key)){

            String requestDemo = "POST / HTTP/1.1\n" +
                    "Host: %s\n" +
                    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0\n" +
                    "Accept: */*\n" +
                    "Content-Type: application/json\n" +
                    "Content-Length: 8\n" +
                    "Connection: close\n" +
                    "\n" +
                    "{\"a\":1'}";
            String scanUrl = httpResponse.getUrl();
            try{
                IHttpRequestResponse messageInfo = BurpSuiteRequests.rawDemo(scanUrl,requestDemo,callbacks);
                HTTPRequests newHttpRequest = new HTTPRequests(callbacks,messageInfo);
                HTTPResponse newHttpResponse = new HTTPResponse(callbacks,messageInfo);

                passiveScanController(newHttpRequest,newHttpResponse,messageInfo,tags,config);
            } catch (Exception e){
                e.printStackTrace();
            } finally {
                activeScanRecord.add(key);
            }
        }

        // TODO：在主动流程最后，增加将结果更新到项目管理列表

    }

    public void fingerAndLanguage(Config config,HTTPResponse httpResponse,IHttpRequestResponse messageInfo){

        Tags tags = config.getTags();
        // 被动指纹识别，如果在界面启动了
        if(tags.getMain2Tag().getFingerCheckBox().isSelected()) {
            new FingerController(config, httpResponse);
        }

        // 如果启动了编程语言识别
        if(tags.getMain2Tag().getLanguageCheckBox().isSelected()){
            languageAnalysis(config,httpResponse);
        }

        // 将指纹最后再录入到页面，因为有些字段信息需要其他被动模块来提供
        Set<String> fingerResult = config.getFingerResult();
        for(int i=0;i<httpResponse.getFingers().size();i++){
            String key = httpResponse.getHost() + ":" + httpResponse.getFingers().get(i);
            // 判断该指纹是否要添加到queue里，解决重复录入的问题
            if (!fingerResult.contains(key)) {
                // 添加到表格中
                tags.getFingerTagClass().add(
                        httpResponse.getUrl(),
                        httpResponse.getHost(),
                        httpResponse.getTitle(),
                        httpResponse.getServer(),
                        httpResponse.getLength(),
                        httpResponse.getStatus(),
                        httpResponse.getFingers().get(i),
                        httpResponse.getLanguage(),
                        messageInfo
                );
                fingerResult.add(key);
            }
            // 更新项目管理上的指纹逻辑
            {
                if(tags.getProjectTableTag().getProjectOpenList().getDlm().size() == 0) return;
                b:
                for(int j=0;j<tags.getProjectTableTag().getUdatas().size();j++){
                    ProjectTableTag.TablesData tablesData = tags.getProjectTableTag().getUdatas().get(j);
                    String url = tablesData.getUrl();
                    String finger = tablesData.getFinger();
                    if(url.equals(httpResponse.getHost())){
                        String newFinger = "";
                        // 如果表格中，当前的行的指纹为空
                        if(finger.isEmpty()){
                            newFinger = httpResponse.getFingers().get(i);
                        }
                        // 如果表格中，当前的行的指纹不为空
                        else{
                            // 判断当前的指纹和即将补充的指纹是否有重复
                            if(finger.contains(",")){
                                String[] fingers = finger.split(",");
                                List<String> temp = Arrays.asList(fingers);
                                // 如果包含
                                if (temp.contains(httpResponse.getFingers().get(i))){
                                    break b;
                                }
                                // 如果不包含
                            }
                            else{
                                // 如果包含
                                if(finger.contains(httpResponse.getFingers().get(i))){
                                    break b;
                                }
                                // 如果不包含
                            }
                            newFinger = finger + "," + httpResponse.getFingers().get(i);
                        }
                        tablesData.setFinger(newFinger);
                        // TODO：刷新数据库
                        config.getDbHelper().updateUrlTable(url,"finger",newFinger);
                        // 刷新表格
                        tags.getProjectTableTag().getTargetTable().repaint();
                        // 退出循环
                        break b;
                    }
                }
            }
        }
    }

    /**
     * 控制器：被动分析
     * @param httpResponse
     * @param tags
     * @param messageInfo
     */
    public void passiveScanController(HTTPRequests httpRequests, HTTPResponse httpResponse, IHttpRequestResponse messageInfo, Tags tags, Config config){

        if (httpResponse == null || messageInfo == null || messageInfo.getResponse() == null) return;

        // 指纹和编程语言放一个模块一起整
        fingerAndLanguage(config,httpResponse,messageInfo);

        // 如果开启了ssrf被动分析
        if(tags.getMain2Tag().getSSRFCheckBox().isSelected()){
            // 基于请求的SSRF检测，录入脆弱性表格中
            String msg = passiveSSRFCheck(httpRequests);
            if (msg != null) {
                String message = "疑似存在SSRF，匹配到关键字：" + msg;
                // TODO
                String level = "低";
                String key = httpResponse.getHost() + ":" + message;
                // 将数据直接录入到前台
                Tools.addInfoToVulnTags(config, tags, httpResponse, message,level, key, messageInfo);
            }
        }

        // 被动列目录检测
        if(tags.getMain2Tag().getListDirectoryCheckBox().isSelected() && passiveListDirectoryCheck(httpResponse)){
            String message = "存在目录枚举，可查看文件/目录";
            // TODO: 改成从配置文件拿
            String level = "中";
            String key = httpResponse.getHost()+":"+message;
            // 将数据直接录入到前台
            Tools.addInfoToVulnTags(config,tags,httpResponse,message,level,key,messageInfo);
        }

        // 是否启动被动信息泄漏分析
        if(tags.getMain2Tag().getInfoLeakCheckBox().isSelected()){
            // 敏感信息匹配
            ArrayList<String> messages = passiveInfoLeakCheck(httpResponse, config);
            for (String message : messages) {
                String key = httpResponse.getHost() + ":" + message;
                // TODO
                String level = "低";
                // 将数据直接录入前台
                Tools.addInfoToVulnTags(config, tags, httpResponse, message,level, key, messageInfo);
            }
        }

        // 是否启动敏感路径检测功能
        if(tags.getMain2Tag().getSensitiveCheckBox().isSelected()){
            // 上传目录检测
            ArrayList<String[]> messages = passiveSensitivePathCheck(httpResponse,config);
            for(String[] _messageInfo : messages){
                String level = _messageInfo[0];
                String message = _messageInfo[1] + _messageInfo[2];
                String key = httpResponse.getHost() + ":" + message;
                // 录入
                Tools.addInfoToVulnTags(config,tags,httpResponse,message,level,key,messageInfo);
            }
        }
    }

    /**
     * 对当前网页的路径进行敏感分析检测，看是否可能存在可利用的
     * @param httpResponse
     */
    public ArrayList<String[]> passiveSensitivePathCheck(HTTPResponse httpResponse, Config config){
        // 定义一个二维数组
        ArrayList<String[] > allResult = new ArrayList<String[]>();
        JSONObject sensitivePathInfo = config.getSensitivePathJsonInfo();
        first:
        for(Map.Entry<String,Object> entry: sensitivePathInfo.entrySet()){
            String vulPath = "";
            String type = entry.getKey();
            // admin / upload 这种
            JSONArray keys = sensitivePathInfo.getJSONObject(type).getJSONArray("key");
            second:
            for(int i=0;i<keys.size();i++){
                // 路径关键字，用来做匹配，并且全部改成小写
                String key = keys.getString(i).toLowerCase(Locale.ROOT);
                // 拿出response里的路径来对比
                third:
                for(String linkPath:httpResponse.getCurrentSameHostLinks()){
                    // 如果关键字 在 路径当中
                    if(linkPath.toLowerCase(Locale.ROOT).contains(key)){
                        vulPath = linkPath;
                        break second;
                    }
                }
            }
            String level = sensitivePathInfo.getJSONObject(type).getString("level");
            String message = sensitivePathInfo.getJSONObject(type).getString("message");
            // 如果匹配到了敏感路径，就要录入
            if(!vulPath.isEmpty()){
                allResult.add(new String[]{level,message,vulPath});
            }
        }

        return allResult;
    }

    /**
     * 对响应报文
     * @param httpResponse
     * @return
     */
    public void languageAnalysis(Config config,HTTPResponse httpResponse){
        // 1. 通过已识别的组件指纹来进行判断编程语言
        {
            JSONObject fingerJsonInfo = config.getFingerJsonInfo();
            ArrayList<String> fingers = httpResponse.getFingers();
            for(int i=0;i<fingers.size();i++){
                String finger = fingers.get(i);
                String language = fingerJsonInfo.getJSONObject(finger).getString("Language");
                if(language!=null){
                    httpResponse.setLanguage(language);
                    return;
                }
            }
        }
        // 2. 采取头部字段分析的方式进行
        JSONObject languageJsonInfo = config.getLanguageFingerJsonInfo();
        {
            for(Map.Entry<String,Object> entry: languageJsonInfo.entrySet()){
                String language = entry.getKey();
                for(Map.Entry<String,Object> entry2: languageJsonInfo.getJSONObject(language).getJSONObject("Headers").entrySet()){
                    // header的名字，如：Server、Set-Cookie
                    String headerName = entry2.getKey();
                    // 先判断一下当前的headerName，在当前的response里有没有；如果没有，就continue；如果有，流程就继续往下走
                    if(!httpResponse.getHeaders().containsKey(headerName)){
                        continue;
                    }
                    // header具体的关键字
                    JSONArray headerValues = languageJsonInfo.getJSONObject(language).getJSONObject("Headers").getJSONArray(headerName);
                    for(int i=0;i<headerValues.size();i++){
                        String headerValue = headerValues.getString(i);
                        // 进行判断，如果匹配，就退出
                        if(((String)httpResponse.getHeaders().get(headerName)).toLowerCase(Locale.ROOT).contains(headerValue.toLowerCase(Locale.ROOT))){
                            httpResponse.setLanguage(language);
//                            config.getConsoleTextArea().append("URL：" + httpResponse.getUrl() + "识别到：" + language);
                            return;
                        }
                    }
                }
            }
        }
        // 3. 通过body的一些关键字进行识别
        {
            for(Map.Entry<String,Object> entry: languageJsonInfo.entrySet()) {
                String language = entry.getKey();
                JSONArray bodyInfo = languageJsonInfo.getJSONObject(language).getJSONArray("Body");
                for (int i = 0; i < bodyInfo.size(); i++) {
                    String key = bodyInfo.getString(i);
                    if (httpResponse.getStrBody().toLowerCase().contains(key.toLowerCase())) {
                        httpResponse.setLanguage(language);
//                        config.getConsoleTextArea().append("URL：" + httpResponse.getUrl() + "识别到：" + language);
                        return;
                    }
                }
            }
        }

        // TODO: 其他指纹识别的方式
        // 3. 采取对目录后缀的方式进行识别，如.php
    }


    /**
     * 对请求报文进行分析，查看里面是否有链接
     * @param httpRequests
     * @return
     */
    public String passiveSSRFCheck(HTTPRequests httpRequests){
        String regex = "https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]";
        Pattern r = Pattern.compile(regex);
        List<IParameter> parameterList = httpRequests.getParameterList();
        for(IParameter i: parameterList){
            String value = i.getValue();
            Matcher m = r.matcher(value);
            if(m.find()){
                return m.group(0);
            }
        }

        return null;
    }


    /**
     * 被动：列目录识别
     */
    public boolean passiveListDirectoryCheck(HTTPResponse httpResponse){
        // 应用于直接的关键字匹配
        ArrayList<String> matchList = new ArrayList<String>(Arrays.asList(
            "转到父目录",
            "parent directory",
            "index of/",
            "index of /",
            "directory listing for",
            "directory of /"
        ));
        // 应用于正则匹配，例如： 10.1.1.1 - /
        ArrayList<String> regexList = new ArrayList<>(Arrays.asList(
            "[a-zA-Z]{0,62}(\\.[a-zA-Z][a-zA-Z]{0,62})+\\.?" + " - /",
            "[0-9]{0,62}(\\.[0-9][0-9]{0,62})+\\.?" + " - /"
        ));

        for(String matchKey:matchList){
            // 说明匹配到了关键字
            if(httpResponse.getResponseRaw().toLowerCase().indexOf(matchKey) != -1){
                return true;
            }
        }

        String title = Tools.getTitle(httpResponse.getResponseRaw());
        if(title.length() > 0){
            for(String regex:regexList){
                Pattern p = Pattern.compile(regex);
                Matcher m = p.matcher(title);
                if(m.find()){
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 被动：敏感关键词匹配
     */
    public ArrayList<String> passiveInfoLeakCheck(HTTPResponse httpResponse,Config config){

        JSONObject infoLeakJson = config.getInfoLeakJsonInfo();
        ArrayList<String> messages = new ArrayList<>();
        for(Map.Entry<String,Object> entry: infoLeakJson.entrySet()){
            String vulnsTypeName = entry.getKey();
            String type = infoLeakJson.getJSONObject(vulnsTypeName).getString("type");
            // 只进行内容匹配
            if(type.indexOf("str")!=-1){
                JSONArray keys = infoLeakJson.getJSONObject(vulnsTypeName).getJSONArray("keys");
                lable1:
                for(Object key:keys){
                    // 说明body命中了关键字
                    if(httpResponse.getStrBody().toLowerCase().indexOf(((String)key).toLowerCase(Locale.ROOT)) != -1){
                        String message = "存在敏感数据泄漏，类型为：" + vulnsTypeName + "，匹配到关键字："+key;
                        System.out.println(message);
                        messages.add(message);
                        break lable1;
                    }
                }
            }
            // 通过正则匹配
            else if(type.indexOf("regex")!=-1){
                String regex = infoLeakJson.getJSONObject(vulnsTypeName).getString("regex");
                Pattern r = Pattern.compile(regex);
                Matcher m = r.matcher(httpResponse.getStrBody().toLowerCase());
                // 说明body命中了关键字
                if (m.find()){
                    String message = "存在敏感数据泄漏，类型为：" + vulnsTypeName + "，匹配到关键字："+m.group(1);
                    messages.add(message);
                }
            }

        }
        return messages;
    }
}

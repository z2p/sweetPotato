package burp.Bootstrap;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.Ui.Tags;
import com.alibaba.fastjson.*;
import com.google.common.hash.Hashing;
import org.apache.commons.lang3.StringEscapeUtils;

import java.util.*;


public class Tools {

    final static String ls = System.getProperty("line.separator");


    public static String URLDecoderString(String str) {

        String result = "";
        if (null == str) {
            return "";
        }
        try {
            result = java.net.URLDecoder.decode(str, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 当传入非http的内容，将其优化成 http://xxx.xxx 或 https://xxx.xxx
     * @return
     */
    public static String UrlAndPortToHttpProtocol(String target){

        if(target.startsWith("https://") || target.startsWith("http://")){
            return target;
        }
        else{
            // 如果输入的内容带：
            if(target.contains(":")){
                String port = target.split(":")[1];
                // 如果端口带443，就是https
                if(port.contains("443")){
                    return "https://" + target;
                }
                else{
                    return "http://" + target;
                }
            }
            else{
                return "http://" + target;
            }
        }
    }

    /**
     * 修改响应报文中的状态码
     * @param responseRaw 完整数据报文
     * @return
     */
    public static byte[] changeStatus(byte[] responseRaw){

        String temp = new String(responseRaw);
        temp = temp.replaceFirst("401","200").replaceFirst("302","200");
        return temp.getBytes();
    }

    /**
     * 自动往vulntags界面里添加数据，并且会自动根据提供的key进行去重
     * @param tags
     * @param httpResponse
     * @param message
     * @param key
     * @param messageInfo
     */
    public static void addInfoToVulnTags(Config config, Tags tags, HTTPResponse httpResponse, String message,String level, String key, IHttpRequestResponse messageInfo){

        Set<String> vulnResult = config.getVulnsResult();
        if(!vulnResult.contains(key)){
            vulnResult.add(key);
            tags.getVulnsTagClass().add(
                    httpResponse.getUrl(),
                    httpResponse.getTitle(),
                    message,
                    httpResponse.getServer(),
                    httpResponse.getLanguage(),
                    level,
                    httpResponse.getLength(),
                    httpResponse.getStatus(),
                    messageInfo
            );
        }
    }

    /**
     * 用来获取当前指纹，有的目录扫描数量
     */
    public static int getFingerSensitivePathCount(JSONObject jsonInfo,String finger){
        int sensitivePathCount = 0;
        try{
            sensitivePathCount = jsonInfo.getJSONObject(finger).getJSONObject("SensitivePath").size();
        } catch (Exception e){ }
        return sensitivePathCount;
    }

    /**
     * 将提供的数据进行分析，分析是否匹配上指纹
     *
     * headers：头部list
     * responseRaw：整个响应报文，包含http头
     * jsonInfo：json配置文件的内容
     */
    public static ArrayList<String> fingerMatch(HashMap<String,Object> headers,String strBody,JSONObject jsonInfo,int responseHash){

        ArrayList<String> fingers = new ArrayList<String>();
        for(Map.Entry<String,Object> entry: jsonInfo.entrySet()){
            String appName = entry.getKey();
            // 做头部匹配
            for (Map.Entry<String,Object> headerInfo: jsonInfo.getJSONObject(appName).getJSONObject("Headers").entrySet()){
                String headerKey = headerInfo.getKey();
                String headerValue = headerInfo.getValue().toString();
                // 如果headerkey在里面，并且value在里面
                if(headers.containsKey(headerKey)){
                    if(headers.get(headerKey).toString().toLowerCase(Locale.ROOT).contains(headerValue.toLowerCase(Locale.ROOT))){
                        fingers.add(appName);
                    }
                }
            }

            // 做body的内容匹配
            for (Map.Entry<String,Object> bodyInfo: jsonInfo.getJSONObject(appName).getJSONObject("Body").entrySet()){
                String bodyPath = bodyInfo.getKey();
                int bodySize = jsonInfo.getJSONObject(appName).getJSONObject("Body").getJSONArray(bodyPath).size();
                for(int i=0;i<bodySize;i++){
                    // 每个关键的key
                    String key = jsonInfo.getJSONObject(appName).getJSONObject("Body").getJSONArray(bodyPath).getString(i).toLowerCase();
                    // 说明命中指纹了
                    if(strBody.toLowerCase().indexOf(key) != -1){
                        fingers.add(appName);
                        break;
                    }
                }
            }

            // 做icon hash的匹配
            int bodySize = jsonInfo.getJSONObject(appName).getJSONArray("Icon_Hash").size();
            for(int i=0;i<bodySize;i++){
                // 每个的hash
                JSONArray icon_hashs = jsonInfo.getJSONObject(appName).getJSONArray("Icon_Hash");
                int hash = (int)icon_hashs.get(i);
                if(responseHash == hash){
                    fingers.add(appName);
                    break;
                }
            }
        }

        // 去重返回，["指纹a","指纹b"]
        return new ArrayList<String>(new HashSet<String>(fingers));
    }

    /**
     * 读取文件，并将内容转化成string返回，适合读取文本文件
     * @param filePath
     * @param isIgnoreNotesLine 如果为true，则当该行是以 // 打头就不加入
     * @return
     */
    public static String readFile(String filePath,boolean isIgnoreNotesLine){

        BufferedReader br = null;
        String line = null;
        StringBuilder sb = new StringBuilder();
        try {
            br = new BufferedReader(new FileReader(filePath));
            while ((line = br.readLine()) != null) {
                if(isIgnoreNotesLine && line.trim().startsWith("//")){
                    continue;
                }
                sb.append(line);
                sb.append(ls);
            }
            return sb.toString();

        } catch (Exception e){
            e.printStackTrace();
        }finally {
            try {
                br.close();
            } catch (Exception e){}
        }
        return null;
    }

    public static String readFile(File file,boolean isIgnoreNotesLine){

        BufferedReader br = null;
        String line = null;
        StringBuilder sb = new StringBuilder();
        try {
            br = new BufferedReader(new FileReader(file));
            while ((line = br.readLine()) != null) {
                if(isIgnoreNotesLine && line.trim().startsWith("//")){
                    continue;
                }
                sb.append(line);
                sb.append(ls);
            }

            return sb.toString();

        } catch (Exception e){
            e.printStackTrace();
        }finally {
            try {
                br.close();
            } catch (Exception e){}
        }
        return "";
    }

    /**
     * 根据用户提供的长度限制，对byte数组进行修剪，注意：会在前方增加提示内容
     * @param byteRaw
     * @param length
     * @return
     */
    public static byte[] cutByte(byte[] byteRaw,int length){

        byte[] message = ("// only show " + length + " length size message\n").getBytes();
        byte[] finalMessage = new byte[length];
        try{
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(message);
            bos.write(byteRaw);
            byte[] tempArray = bos.toByteArray();
            ByteArrayInputStream bis = new ByteArrayInputStream(tempArray);
            bis.read(finalMessage);
        } catch (Exception e){}
        return finalMessage;
    }

    /**
     * 打开json文件并将其内容解析，把json对象返回
     */
    public static JSONObject getJSONObject(String filePath) throws Exception{

        JSONObject json = null;
        // 读取文件中的内容
        String fileRaw = readFile(filePath,true);
        // 如果读取的对象为null，则应该是出现了异常
        if(fileRaw == null){
            throw new Exception("Json文件加载异常，文件不存在该路径：" + filePath);
        }
        else{
            // 将内容转化成json格式，如果转化出现异常，则是json格式有问题
            try{
                json = JSONObject.parseObject(fileRaw);
            } catch (Exception e){
                throw new Exception("Json解析出现异常：" + filePath + " " + e.getMessage());
            }
        }
        return json;
    }

    /**
     * 当提供一个域名 或者 ip时能判断是不是ip
     * @param domain 两类输入 xx.xxx.xcom || 123.123.123.123 || 123.123.123.123:8080
     * @return
     */
    public static boolean isIP(String domain){
        if(!domain.contains(".")) return false;
        String[] splitInfo = domain.split("\\.");

        for(String info:splitInfo){
            try{
                int i = Integer.parseInt(info);
                if(i>=256 || i<0) return false;
            } catch (Exception e){
                // 只要抛异常，就说明是false
                return false;
            }
        }
//        System.out.println(splitInfo);
        return true;
    }

    /**
     * 将byte转string，主要应用于对burpsuite的response转化成明文
     * @param bytes
     * @param headers 通过头部的部分字段，判断选择转化的编码选择
     * @return
     */
    public static String byteToString(byte[] bytes,HashMap<String,Object> headers){

        String strContent = "";
        String defaultCharset = "utf-8";
        boolean isHeadersContainCharset = false;
        if (null == bytes || bytes.length == 0) {
            return strContent;
        }

        // 尝试通过头部 content-type识别编码方式 https://home.163.com
        if(headers != null && headers.containsKey("Content-Type")){
            String contentTypeValue = headers.get("Content-Type").toString();
            if (contentTypeValue.contains("charset=")){
                String temp = contentTypeValue.split("charset=")[1];
                if(temp.contains(";")){
                    temp = temp.split(";")[0].trim();
                }
                defaultCharset = temp;
                isHeadersContainCharset = true;
            }
        }

        // https://zhidao.baidu.com <meta http-equiv="content-type" content="text/html;charset=gbk" /> 👌
        // http://product.auto.163.com <meta charset="gbk"> 👌
        // http://hz.baidu.com <meta charset="gb2312" />    👌
        // https://value.qq.com <meta charset="gbk" />

        // 如果头部里没charset，就根据body做一些尝试分析
        if(!isHeadersContainCharset){
            // 小写
            String tempChange = new String(bytes).toLowerCase(Locale.ROOT);
            // 临时解决方案，看是否能解决大部分问题
            if(tempChange.contains("<meta charset=\"gbk\">") || tempChange.contains("charset=gbk") || tempChange.contains("charset=\"gbk\"")){
                defaultCharset = "GBK";
            }
            else if(tempChange.contains("charset=gb2312") || tempChange.contains("charset=\"gb2312\"")){
                defaultCharset = "gb2312";
            }
        }

        // 具体转码方式
        try {
            strContent = new String(bytes, defaultCharset);
        } catch (UnsupportedEncodingException e) {
            strContent = new String(bytes);
            e.printStackTrace();
            System.out.println("编码出现了异常");
        }
        return strContent;
    }

    /**
     * 获取标题
     */
    public static String getTitle(String responseRaw){
        String regex = "<title.*?>(.+?)</title>";
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(responseRaw);
        String title = "";
        if (m.find()){
            title = m.group(1);
        }

        // 做一次html实体编码解码
        title = StringEscapeUtils.unescapeHtml4(title);
        return title;
    }

    public static HashMap<String,String> changeStrToHeader(String strHeader){
        HashMap<String,String> headers = new HashMap<>();
        // 1. 解析头部
        String[] infos = strHeader.split("\n");
        // 2. 将头部的内容写到headers里去
        for(String info:infos){
            try{
                List<String> temp = new ArrayList<String>(Arrays.asList(info.split(":")));
                String key = temp.remove(0).trim();
                String value = String.join(":",temp.toArray(new String[temp.size()])).trim();
                // 2.1 如果key已经在头部了，这个时候追加
                if(headers.containsKey(key)){
                    String oldValue = headers.remove(key).trim();
                    headers.put(key,oldValue + "; " + value);
                } else{
                    headers.put(key,value);
                }

            } catch (Exception e){
                System.out.println("异常：" + info);
                e.printStackTrace();
            }
        }

        return headers;
    }

    /**
     * 可对requests/response的头部字段进行添加
     * @param headers 所需要添加的字段的headers
     * @param key 头部header名称
     * @param value header具体值
     * @param isForceInsert 当value中已经存在该字段后，是否还要插入数据 0 追加 1 覆盖
     */
    public static List<String> setHeaders(List<String> headers,String key,String value,int isForceInsert){
        boolean keyIsExists = false;
        int keyIndex = 0;
        for(int i=0;i<headers.size();i++) {
            String header = headers.get(i);
            if (header.startsWith(key)) {
                keyIsExists = true;
                keyIndex = i;
                break;
            }
        }

        // 如果header key已经存在了
        if(keyIsExists){
            String oldHeader = headers.get(keyIndex);
            String _key = oldHeader.substring(0, oldHeader.indexOf(":"));
            String _value = oldHeader.substring(oldHeader.indexOf(":") + 1, oldHeader.length()).trim();
            // 如果要做强制插入，意味着value里面已经有这个信息了，但还是要写
            // isForceInsert：如果key和value已经存在，这个是否value是追加 还是 刷新 还是 不操作？
            // 0 追加 1 覆盖
            if(isForceInsert == 0) {
                headers.remove(keyIndex);
                headers.add(_key + ": " + _value + "; " + value);
            }
            else if(isForceInsert == 1){
                headers.remove(keyIndex);
                headers.add(key + ": " + value);
            }
        }
        else{
            headers.add(key + ": " + value);
        }

        return headers;
    }

    public static List<String> deleteHeader(List<String> headers,String key){
        boolean keyIsExists = false;
        int keyIndex = 0;
        for(int i=0;i<headers.size();i++) {
            String header = headers.get(i);
            if (header.startsWith(key)) {
                keyIsExists = true;
                keyIndex = i;
                break;
            }
        }
        if(keyIsExists){
            headers.remove(keyIndex);
        }

        return headers;
    }

    //Unicode转中文方法
    public static String unicodeToCn(String unicode) {
        /** 以 \ u 分割，因为java注释也能识别unicode，因此中间加了一个空格*/
        String[] strs = unicode.split("\\\\u");
        String returnStr = "";
        // 由于unicode字符串以 \ u 开头，因此分割出的第一个字符是""。
        for (int i = 1; i < strs.length; i++) {
            returnStr += (char) Integer.valueOf(strs[i], 16).intValue();
        }
        return returnStr;
    }

    // 获取body
    public static byte[] getBody(boolean isRequest, byte[] raw, IExtensionHelpers helpers){
        int bodyOffset = -1;
        if (isRequest){
            bodyOffset = helpers.analyzeRequest(raw).getBodyOffset();
        }
        else {
            bodyOffset = helpers.analyzeResponse(raw).getBodyOffset();
        }
        byte[] byteBody = Arrays.copyOfRange(raw,bodyOffset,raw.length);
        return byteBody;
    }

    public static int calcHash(byte[] content) {
        String base64Str = new BASE64Encoder().encode(content);
        int hashvalue = Hashing.murmur3_32().hashString(base64Str.replaceAll("\r","")+"\n", StandardCharsets.UTF_8).asInt();
        return hashvalue;
    }

    public static void openBrowser(String url,String browserPath) throws Exception{

        // TODO：非安全调用
        if(url.startsWith("http://") || url.startsWith("https://")){
            String[] cmdArray = new String[]{browserPath,url};
            Runtime.getRuntime().exec(cmdArray);
        }
    }

    public static boolean isMac(){
        String os = System.getProperty("os.name").toLowerCase();
        return (os.indexOf( "mac" ) >= 0);
    }

    /**
     * 获取-插件运行路径
     *
     * @return
     */
    public static String getExtensionFilePath(IBurpExtenderCallbacks callbacks) {
        String path = "";
        Integer lastIndex = callbacks.getExtensionFilename().lastIndexOf(File.separator);
        path = callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
        return path;
    }

    /**
     * 判断文件后缀是否在黑名单里，如果在，则返回true；不在则返回false
     */
    public static boolean fileSuffixIsInBlackList(String fileSuffix){
        boolean inBlackList = false;
        String[] blackList = new String[]{"3g2","3gp","7z","aac","abw","aif","aifc","aiff","arc","au","avi","azw","bin","bmp","bz","bz2","cmx","cod","csh","doc","docx","eot","epub","gif","gz","ico","ics","ief","jar","jfif","jpe","jpeg","jpg","m3u","mid","midi","mjs","mp2","mp3","mpa","mpe","mpeg","mpg","mpkg","mpp","mpv2","odp","ods","odt","oga","ogv","ogx","otf","pbm","pdf","pgm","png","pnm","ppm","ppt","pptx","ra","ram","rar","ras","rgb","rmi","rtf","snd","svg","swf","tar","tif","tiff","ttf","vsd","wav","weba","webm","webp","woff","woff2","xbm","xls","xlsx","xpm","xul","xwd","zip","wmv","asf","asx","rm","rmvb","mp4","mov","m4v","dat","mkv","flv","vob"};
        for(String blackSuffix:blackList){
            if(fileSuffix.equals(blackSuffix)){
                inBlackList = true;
                return inBlackList;
            }
        }
        return inBlackList;
    }

    /**
     *
     * @param url httpResponse里的url
     * @param host httpResponse里的host
     * @return
     */
    public static String getCurrentPath(String url,String host){
        String currentPath = "";
        String temp = "";
        temp = url.substring(host.length());
        // 如果结果为 / 或者为空 说明就是在根目录
        if(temp.equals("/") || temp.length() == 0){
            currentPath = "/";
        }
        // 找最后一个 / 然后重组
        else{
            currentPath = temp.substring(0,temp.lastIndexOf("/")+1);
        }
        return currentPath;
    }

    /**
     * 从文件按行提取内容，或者是单个url
     * @param input
     * @return
     */
    public static ArrayList<String> getUrls(String input){
        ArrayList<String> arrayListUrls = new ArrayList<String>();
        HashSet<String> urls = new HashSet<String>();
        if(input.startsWith("https://") || input.startsWith("http://")){
            urls.add(input.trim());
        }
        else if(input.startsWith("file://")){
            String fileResult = readFile(input.replace("file://",""),false);
            String[] fileLines = fileResult.split(ls);
            for(String line :fileLines){
                line = hostPortToUrl(line);
                if(line.length() >0) {
                    urls.add(line);
                }
            }
        }

        // 利用hashset做了一次去重
        for(String url:urls){
            arrayListUrls.add(url);
        }

        return arrayListUrls;
    }

    /**
     * 提供如： 123.123.123.123:443 会转化成 https://123.123.123.123
     * 123.123.123.123:9443 会转化成 https://123.123.123.123:9443
     *
     * 如果提供的内容有问题，则返回空
     * @param input
     * @return
     */
    public static String hostPortToUrl(String input){
        if(input.startsWith("http://") || input.startsWith("https://")){
            return input.trim();
        }
        else if(input.contains(":")){
            String host = input.split(":")[0];
            String port = input.split(":")[1].trim();

            if(port.equals("443") && port.length() == 3){
                return "https://" + host;
            }
            else if(port.endsWith("443")){
                return "https://" + host + ":" + port;
            }
            else if(port.equals("80") && port.length() == 2){
                return "http://" + host;
            }
            else{
                return "http://" + host + ":" + port;
            }
        }
        return "";
    }

    /**
     * 判断用户输入 是否为一个目录，/index.php 不是目录 /index/ 是目录
     */
    public static boolean getInputIsPath(String path){
        if(path.startsWith("/") && path.endsWith("/")){
            return true;
        }
        return false;
    }

    /**
     * 从一个相对路径里，提取出目录，如： /admin/system/index.php，就可以提取出 /admin/ /admin/system/； 比较复杂，只能实现部分
     * @param path
     * @return
     */
    public static ArrayList<String> getLinkDirectory(String path){

        ArrayList<String> paths = new ArrayList<String>();
        String prefix = "/";

        if(!path.startsWith(prefix)){ return paths;}
        // /xxx/
        if(path.endsWith(prefix) && path.length() != 1){
            // 当前目录要加进去
            paths.add(path);
        }
        else{
            String[] temp = path.split(prefix);
            if(temp.length > 2){
                String newPath = "";
                for(int i=0;i<temp.length-1;i++){
                    if(temp[i].trim().isEmpty()){
                        continue;
                    }
                    newPath += prefix + temp[i];
                }
                newPath += "/";
                paths.add(newPath);
            }
        }
        return paths;
    }

    public static void debugPrint(Object obj){
        System.out.println("=====================");
        System.out.println(obj);
        System.out.println("=====================");
    }
}
package burp.Bootstrap;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import org.apache.commons.lang3.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * 该类用于解析burpsuite提供的对象，来解析成对应的HTTP响应报文字段
 */
public class HTTPResponse {

    int length;         // 整个响应报文长度
    int status;         // 状态码
    String url;         // url fqdn 如：http://xxx.baidxx.com/asdsads/ddd.jsp
    String host;        // host 如：http://xxxx.com:8080
    String domain;      // domain 如： xxx.com 或 111.111.111.111
    boolean isIP;       // 存放是IP还是域名，如果是IP，则为true，不是IP，则为false
    String currentPath; // 用来存储当前的路径，例如 url为http://xxx.baidu.com/aaaadd/s.jsp，则currentPath为 /aaaadd/
    String fileSuffix="";  // 文件后缀，默认为空
    String strResponseRaw; // 响应报文，字符串
    byte[] byteResponseRaw; // 响应报文，byte
    String strBody;     // 内容，str
    byte[] byteBody;    // 内容，byte
    String title;       // 标题
    String server;      // 响应头server
    String language = "unknown";    // 编程语言
    ArrayList<String> fingers;    // 保存指纹
    int iconHash;       // iconHash
    String isCheck = "未开始";
    String assetType = "未分类";
    String comments = "";
    String ip = "";

    HashMap<String,Object> headers = new HashMap<>();   // ok
    HashSet<String> currentAllLinks = new HashSet<>();   // 当前页面的所有链接
    HashSet<String> currentSameHostLinks = new HashSet<>(); // 当前页面的所有拥有相同host的链接，参考String host
    HashSet<String> currentSameDomainLinks = new HashSet<>();   // 当前页面的所有拥有相同domain的链接，参考String domain
    HashSet<String> currentLinkDirectory = new HashSet<>(); // 当前页面的所拥有相同host的目录
    HashSet<String> responseDomain = new HashSet<>();   // 当前页面所有的域名都提取出来，xxx.baidu.com这种

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getIsCheck() {
        return isCheck;
    }

    public String getAssetType() {
        return assetType;
    }

    public String getComments() {
        return comments;
    }

    public String getIp() {
        return ip;
    }

    public HTTPResponse(String url){
        this.url = url;
        this.host = url;
        this.domain = CustomBurpUrl.getDomain(host);
        this.isIP = isIP(url);
        exceptionParaSet();
    }

    public HTTPResponse(byte[] content){ }

    public HTTPResponse(){ }

    public HTTPResponse(IBurpExtenderCallbacks callbacks, IHttpRequestResponse messageInfo){

        IExtensionHelpers helpers = callbacks.getHelpers();
        CustomBurpUrl customBurpUrl = new CustomBurpUrl(callbacks, messageInfo);
        byteResponseRaw = messageInfo.getResponse();

        // 状态码
        this.status = (int) helpers.analyzeResponse(byteResponseRaw).getStatusCode();
        // url，http://xxxxx.xxxcom/xxxx?xxx=1&bbb=xxx
        this.url = customBurpUrl.getHttpRequestUrl(messageInfo,helpers).toString();
        // host，http://xxxx.com/
        this.host = customBurpUrl.getRequestDomainName(messageInfo);
        // headers hashmap
        analysisHeaders(helpers.analyzeResponse(byteResponseRaw).getHeaders());
        // 响应报文
        this.strResponseRaw = Tools.byteToString(byteResponseRaw,headers);
        // 标题
        this.title = Tools.getTitle(strResponseRaw);
        // 逻辑调整，带有location并且状态码为301或302就显示location
        if(headers.containsKey("Location") && (this.status == 302 || this.status == 301)){
            title = "---> " + StringEscapeUtils.unescapeHtml4(headers.get("Location").toString());
        }
        // 响应体
        this.byteBody = Tools.getBody(false,byteResponseRaw, callbacks.getHelpers());
        this.domain = CustomBurpUrl.getDomain(host);
        // 正则提取当前页面的所有域名
        analysisResponseHasDomain(responseDomain,strResponseRaw);

        // 判断是否为IP
        this.isIP = isIP(domain);
        this.strBody = Tools.byteToString(byteBody,headers);
        this.iconHash = Tools.calcHash(this.byteBody);
        this.fingers = new ArrayList<>();
        this.currentPath = Tools.getCurrentPath(url,host);
        this.fileSuffix = customBurpUrl.getFileSuffix();
        // 提取当前页面的所有链接
        this.currentAllLinks = getAllLinks(strBody,headers,strResponseRaw,host);
        this.currentSameHostLinks = getSameHostLinks(currentAllLinks,currentPath,host);
        this.currentSameDomainLinks = getSameDomainLinks(currentAllLinks,domain);
        this.currentLinkDirectory = getCurrentLinkDirectory(currentSameHostLinks);

        if(headers.containsKey("Server")){
            this.server = headers.get("Server").toString();
        }
        else{
            server = "";
        }

        if(headers.containsKey("Content-Length")){
            this.length = Integer.parseInt(headers.get("Content-Length").toString());
        }
        else {
            // 响应长度
            this.length = this.byteBody.length;
        }
    }

    public HashSet<String> getResponseDomain() {
        return responseDomain;
    }

    public static void analysisResponseHasDomain(HashSet<String> responseDomain, String strResponseRaw){

        String html = htmlDecodeFormat(strResponseRaw);
        String regex = "[a-zA-Z]{0,62}(\\.[a-zA-Z][a-zA-Z]{0,62})+\\.?";
        try{
            Pattern r = Pattern.compile(regex);
            Matcher m = r.matcher(html);
            while(m.find()){
                String value = m.group();
                // 如果前面是.
                if(value.startsWith(".")){
                    value = value.substring(0,value.length()-1);
                }
                responseDomain.add(value);
            }

        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * 对网页里的url之类提取，先做一遍的编码转换
     * @return
     */
    public static String htmlDecodeFormat(String html){

        html = html.
                replace("\\/\\/","//").
                replace("\\/","/").
                replace("%3A",":").
                replace("%3a",":").
                replace("%2f","/").
                replace("%2F","/").
                replace("\\u002F","\\").
                replace("\\u002f","\\");
        return html;
    }

    /**
     * 提取网页里的所有链接，当前已完成实现；对应currentAllLinks
     * @param body 响应body
     * @param headers 响应头
     * @param strResponseRaw 整个响应包
     * @return
     */
    public static HashSet<String> getAllLinks(String body,HashMap<String,Object> headers,String strResponseRaw,String host){

        // 临时存放数据使用
        HashSet<String> temp = new HashSet<String>();
        // 定义最后要返回的HashSet
        HashSet<String> currentAllLinks = new HashSet<>();
        // 对网页内容进行一个替换，\/ /，%3A -> :
        String html = htmlDecodeFormat(strResponseRaw);
        // 交给jsoup做数据提取分析
        Document doc = Jsoup.parse(html);

        // 提取链接
        // 1. <script>里的src提取
        {
            Elements srcLinks = doc.select("script[src]");
            for(int i=0;i<srcLinks.size();i++){
                temp.add(srcLinks.get(i).attr("src"));
            }
        }
        // 2. <a>里的href提取
        {
            Elements hrefLinks = doc.select("a[href]");
            for(int i=0;i<hrefLinks.size();i++){
                String href = hrefLinks.get(i).attr("href");
                temp.add(href);
            }
        }
        // 3. <img>里的src提取
        {
            Elements imgLinks = doc.select("img[src]");
            for(int i=0;i<imgLinks.size();i++){
//                System.out.println(imgLinks.get(i).attr("src"));
                temp.add(imgLinks.get(i).attr("src"));
            }
        }
        // 4. <link>里的href提取
        {
            Elements linkLinks = doc.select("link[href]");
            for(int i=0;i<linkLinks.size();i++){
//                System.out.println(imgLinks.get(i).attr("src"));
                temp.add(linkLinks.get(i).attr("href"));
            }
        }

        // 5. 通过header Location提取
        if(headers != null && headers.containsKey("Location")){
            String locationValue = ((String)(headers.get("Location"))).replace("HTTPS://","https://").replace("HTTP://","http://");
            // 如果是绝对路径，那就直接加进去
            if(locationValue.contains("http://") || locationValue.contains("https://")){
                temp.add(locationValue);
            }
            // 如果是相对路径，那就加上当前的host
            else{
                temp.add(host + locationValue);
            }
        }

        // 6. 全文正则匹配
        HashSet<String> temp2 = new HashSet<String>();
        {
            // 使用http的正则匹配
            String regex = "https?://(?:[-\\w.:])+";
            Pattern r = Pattern.compile(regex);
            Matcher m = r.matcher(strResponseRaw);
            while(m.find()){
                String _str = m.group();
                temp2.add(_str);
                temp.add(_str);
            }
        }

        {
            // 使用 // 匹配
            String regex = "//(?:[-\\w.:])+";
            Pattern r = Pattern.compile(regex);
            Matcher m = r.matcher(strResponseRaw);
            while(m.find()){
                String _str = m.group();
                // 必须带两个.以上
                int beforeReplaceLength = _str.length();
                String newStr = _str.replace(".","");
                int afterReplaceLength = newStr.length();
                // 如果带的.小于2个，说明可能不是url
                if(beforeReplaceLength - afterReplaceLength < 2) continue;
                boolean isInHashSet = false;
                d:
                for(String tempStr:temp2){
                    // 如果包含，说明是在hashSet里
                    if(tempStr.contains(_str)){
                        isInHashSet = true;
                        break d;
                    }
                }
                // 如果不在hashset里，则在前面加http:，并加入到temp里
                if(!isInHashSet){
                    temp.add("http:" + _str);
                }
            }
        }

        // 先对提取的数据初步筛选和处理，这里拿到的是 所有当前目录的路径
        for(String tempStr:temp){
            // 如果打头是http 或者 https，那就不需要操作； 👌
            if(tempStr.startsWith("https://") || tempStr.startsWith("http://")){
                // 做多一层过滤
                if(Tools.isIllegalCharInUrl(tempStr)) continue;
            }
            // 如果打头是//，拼接http: 👌 TODO：看是不是需要优化，会不会存在 //结果后面是443端口之类的
            else if(tempStr.startsWith("//")){
                tempStr = "http:" + tempStr;
            }
            // 如果整个内容是 javascript:;就不做处理 或者全部只是 / 或者是 #
            else if(tempStr.contains("javascript:") || tempStr.equals("/") || tempStr.startsWith("#")){ continue; }
            // 如果打头是 / 并且不只是 /，直接添加就可以了 TODO:后面可以改成 http://xxxxx 当前路径 拼接
            else if(tempStr.startsWith("/") && !tempStr.equals("/")){ }
            // 如果打头是 ..，则要将目录做一定的切换，或者粗暴一点直接合并
            else if(tempStr.startsWith("../")){
                // TODO
            }
            // 如果打头是 ./，则忽略点
            else if(tempStr.startsWith("./")){
                tempStr = tempStr.substring(1);
            }
            // 如果是data base64的图片，也做忽略
            else if(tempStr.startsWith("data:image/png;base64")){
                continue;
            }
            // 如果其中带有特殊字符也做过滤，该函数判断如果存在不合法的字符会返回true
            else if(Tools.isIllegalCharInUrl(tempStr)){
                continue;
            }
            // 剩余就先当作是 aaa.html 直接是文件名的情况处理
            else{
                tempStr = "/" + tempStr;
            }
            // 再做一层过滤和提取，如果完整链接带有#，将#截断处理，然后评估#前的内容，是否重复
            if(tempStr.contains("#")){
                tempStr = tempStr.substring(0,tempStr.indexOf("#")-1);
            }
            // 加入到alllinks
            currentAllLinks.add(tempStr);
        }

        return currentAllLinks;
    }

    /**
     * 根据currentAllLinks提取同host的链接，需要提供host，host参考String host的标准定义
     * @return
     */
    public static HashSet<String> getSameHostLinks(HashSet<String> currentAllLinks,String currentPath,String host){

        HashSet<String> currentSameHostLinks = new HashSet<String>();
        // 先对提取的数据初步筛选和处理，这里拿到的是 所有当前目录的路径
        for(String tempStr:currentAllLinks){
            // 如果打头是http 或者 https，那就不需要操作； 👌
            if(tempStr.startsWith("https://") || tempStr.startsWith("http://")){
                // 如果携带的host与当前url并不一致
                if(!tempStr.contains(host)){
                    continue;
                }
            }
            // 如果打头是 / 并且不只是 /，说明是该host的链接，拼接一下
            else if(tempStr.startsWith("/") && !tempStr.equals("/")){
                tempStr = host.substring(0,host.length()-1) + tempStr;
            }
            // 如果打头是 ..，则要将目录做一定的切换，或者粗暴一点直接合并
            else if(tempStr.startsWith("../")){
                // TODO
                tempStr =  currentPath + tempStr;
            }
            // 如果打头是 ./，则忽略点
            else if(tempStr.startsWith("./")){
                tempStr = tempStr.substring(1);
            }
            // 剩余就先当作是 aaa.html 直接是文件名的情况处理
            else{
                tempStr = "/" + tempStr;
            }

            currentSameHostLinks.add(tempStr);
        }
        return currentSameHostLinks;
    }

    /**
     * 根据currentAllLinks提取相同domain的链接，需要提供domain，domain参考String domain的标准定义
     * @param currentAllLinks
     * @param domain
     * @return
     */
    public static HashSet<String> getSameDomainLinks(HashSet<String> currentAllLinks, String domain){

        HashSet<String> currentSameDomainLinks = new HashSet<String>();
        for(String link:currentAllLinks){
            // 如果带有这个域名，则认为是目标
            if(link.contains(domain)){
                // 要将link转化成host，即 http[s]://xxxxx.xxx[:8080] 这种类型，结尾不带/
                String host = changeFQDNURLToHost(link);
                currentSameDomainLinks.add(host);
            }
        }

        return currentSameDomainLinks;
    }

    /**
     * 根据currentSameHostLinks提取当前下的目录结构
     * @param currentSameHostLinks
     * @return
     */
    public static HashSet<String> getCurrentLinkDirectory(HashSet<String> currentSameHostLinks){

        HashSet<String> currentLinkDirectory = new HashSet<String>();
        // 提取目录 TODO: 还可以优化
        for(String tempStr:currentSameHostLinks){
            ArrayList<String> paths = Tools.getLinkDirectory(tempStr);
            for(String path:paths){
                currentLinkDirectory.add(path);
            }
        }

        return currentLinkDirectory;
    }


    public HashSet<String> getCurrentLinkDirectory() {
        return currentLinkDirectory;
    }

    public void analysisHeaders(List<String> _headers){
        for(int i=0;i<_headers.size();i++){
            String tempHeader = _headers.get(i);
            if(tempHeader.contains(":")) {
                String key = tempHeader.substring(0, tempHeader.indexOf(":"));
                String value = tempHeader.substring(tempHeader.indexOf(":")+1, tempHeader.length()).trim();
                // 加多一层判断，如果这个key已经在Header里了，就追加value
                if(this.headers.containsKey(key)){
                    String oldValue = this.headers.get(key).toString();
                    this.headers.put(key,oldValue + "; " + value);
                }
                // 如果不在，则新建一个key
                else{
                    this.headers.put(key,value);
                }
            }
        }

    }

    public String getFileSuffix() {
        return fileSuffix;
    }

    public void setFileSuffix(String fileSuffix) {
        this.fileSuffix = fileSuffix;
    }

    public String getCurrentPath() {
        return currentPath;
    }

    public ArrayList<String> getFingers() {
        return fingers;
    }

    public void setFingers(ArrayList<String> fingers) {
        this.fingers = fingers;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public int getIconHash() {
        return iconHash;
    }

    public void setIconHash(int iconHash) {
        this.iconHash = iconHash;
    }

    public String getServer(){
        return server;
    }

    public int getLength() {
        return length;
    }

    public int getStatus() {
        return status;
    }

    public String getUrl() {
        return url;
    }

    public String getHost() {
        return host;
    }

    public String getResponseRaw() {
        return strResponseRaw;
    }

    public String getStrBody(){
        return strBody;
    }

    public String getTitle() {
        return title;
    }

    public HashMap<String, Object> getHeaders() {
        return headers;
    }

    /**
     * 当提供的callback或者是messageInfo存在问题时，将参数都置为异常
     */
    public void exceptionParaSet(){

        this.length = -1;
        this.status = -1;
        this.strResponseRaw = "";
        this.title = "Exception";
        this.byteBody = new byte[]{};
        this.strBody = "";
        this.iconHash = -1;
        this.fingers = new ArrayList<>();
        this.currentPath = "";
        this.fileSuffix = "";
        this.server = "Exception";
    }

    public static String getIP(String domain){
        try{
            String ips = Inet4Address.getByName(domain).getHostAddress();
            return ips;
        } catch (UnknownHostException e){

        } catch (Exception e){
            e.printStackTrace();
        }
        return "Exception";
    }

    public boolean isIP() {
        return isIP;
    }

    public static boolean isIP(String domain){

        String type = "";
        // 先初步判断是否存在关键字，例如ipv4是用.拼接，ipv6是用:拼接，如果都不存在则直接返回
        if(domain.contains("\\.")){
            type = "ipv4";
        }
        else if(domain.contains(":")){
            type = "ipv6";
        }
        else{
            return false;
        }

        if(type.equals("ipv4")){
            try {
                return Inet4Address.getByName(domain).getHostAddress().equals(domain);
            }catch (Exception e){
                return false;
            }
        }
        else if(type.equals("ipv6")){
            try{
                return Inet6Address.getByName(domain).getHostAddress().equals(domain);
            }catch (Exception e){
                return false;
            }
        }

        return true;
    }

    public HashSet<String> getCurrentAllLinks() {
        return currentAllLinks;
    }

    /**
     * 将 http://xxxxxxx.xxx/xxxx?id=xxxx 转化成 http://xxxxxxx.xxxx/
     * @return
     */
    public static String changeFQDNURLToHost(String fqdn){

        String prefix = "";
        String temp = "";
        if(fqdn.startsWith("http://")){
            prefix = "http://";
        }
        else if(fqdn.startsWith("https://")){
            prefix = "https://";
        }

        temp = fqdn.replace("http://","").replace("https://","");
        if(temp.contains("/")){
            temp = temp.split("/")[0];
        }

        if(temp.contains("?")){
            temp = temp.split("\\?")[0];
        }

        return prefix + temp;
    }

    public String toString(){
        String message = "";
        message += "===============================\n";
        message += "Url： " + url + "\n";
        message += "Host： " + host + "\n";
        message += "Domain： " + domain + "\n";
        message += "CurrentPath： " + currentPath + "\n";
        message += "FileSuffix：" + fileSuffix + "\n";
        message += "Title： " + title + "\n";
        message += "Server： " + server + "\n";
        message += "Language： " + language + "\n";
        message += "IconHash： " + iconHash + "\n";
        message += "Length： " + length + "\n";
        message += "Status： " + status + "\n";
        message += "Finger： " + fingers.toString() + "\n";
        message += "Headers：\n";
        for(Map.Entry <String,Object> entry:headers.entrySet()){
            message += "    " + entry.getKey() + ": " + entry.getValue().toString() + "\n";
        }
        message += "===============================\n";
        return message;
    }

    public String getDomain() {
        return domain;
    }

    public HashSet<String> getCurrentSameHostLinks() {
        return currentSameHostLinks;
    }


}

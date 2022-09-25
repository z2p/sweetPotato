package burp.Controller;

import burp.Bootstrap.JsonFormat;
import burp.Bootstrap.Tools;
import burp.IExtensionHelpers;
import burp.IRequestInfo;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrettyTagController {

    /**
     *  整个对数据包美化的处理流程
     * @param content 整个数据包
     * @param isRequest
     * @param helpers
     * @return
     */
    public byte[] pretty(byte[] content,boolean isRequest,IExtensionHelpers helpers){
        List<String> headers;
        if(isRequest){
            headers = helpers.analyzeRequest(content).getHeaders();
        }
        else{
            headers = helpers.analyzeResponse(content).getHeaders();
        }
        byte[] byteBody = Tools.getBody(isRequest,content,helpers);
        // 先跑json格式优化
        byteBody = jsonFormatToTextPanel(isRequest,content,byteBody,helpers);
        // 再跑unicode解码
        byteBody = unicodeToCNToTextPanel(byteBody);
        // 去除多余的换行符号
        byteBody = ignoreMoreCRLF(byteBody,8);
        byte[] raw = helpers.buildHttpMessage(headers,byteBody);    // 组装成完整的数据包
        return raw;
    }

    /**
     * 针对请求和响应报文进行json格式的美化
     * @param isRequest
     * @param content
     *
     * 返回的内容只有body
     */
    public byte[] jsonFormatToTextPanel(boolean isRequest,byte[] content, byte[] byteBody, IExtensionHelpers helpers){
        if(isRequest){
            if(helpers.analyzeRequest(content).getContentType() != IRequestInfo.CONTENT_TYPE_JSON){
                return byteBody;
            }
        }
        else{
            // 如果提供的数据类型不是json，就直接跳过了
            if(!helpers.analyzeResponse(content).getInferredMimeType().equals("JSON")){
                return byteBody;
            }
        }
        String strBody = new String(byteBody);
        String body = new JsonFormat(strBody).getFormatResult();
        return body.getBytes();
    }

    public byte[] unicodeToCNToTextPanel(byte[] content){
        String body = new String(content);
        String regex = "(\\\\u(\\p{XDigit}{4}))";
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(body);
        while(m.find()){
            String oldValue = m.group(1);
            String newValue = Tools.unicodeToCn(oldValue);
            body = body.replace(oldValue,newValue);
        }
        byte[] byteBody = body.getBytes();
        return byteBody;
    }

    public byte[] ignoreMoreCRLF(byte[] byteBody,int times){
        String body = new String(byteBody);
        String crlf = "\r\n";
        for(int i=0;i<times;i++){
            body = body.replace(crlf+crlf,crlf).replace("\t"+crlf,crlf);
        }
        return body.getBytes();
    }

}

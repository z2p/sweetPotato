package burp;
import burp.Bootstrap.HTTPResponse;
import burp.Bootstrap.Tools;
import com.alibaba.fastjson.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;


public class Test
{
    public static void main(String args[]) throws Exception
    {
        String domainName = "www.baidu.com";
        for(InetAddress inetAddress:InetAddress.getAllByName(domainName)){
            System.out.println(inetAddress.getHostAddress());
        }
    }
}
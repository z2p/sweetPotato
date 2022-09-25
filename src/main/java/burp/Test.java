package burp;
import burp.Bootstrap.HTTPResponse;
import burp.Bootstrap.Tools;
import com.alibaba.fastjson.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;


public class Test
{
    public static void main(String args[])
    {
        String test = "aaa.bbbb.ccc";

        Tools.isIP(test);
    }
}
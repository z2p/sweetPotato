package burp.Bootstrap;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;

public class JsonFormat {

    String formatResult = "";
    public JsonFormat(String jsonInfo){

        InputStream inputStream = new ByteArrayInputStream((jsonInfo).getBytes());
        InputStreamReader in = new InputStreamReader(inputStream);
        int read = 0;
        int indent = 0;
        try {

            while ((read = in.read()) > 0) {
                char ch = (char) read;
                switch (ch) {
                    case '{': {
                        indent = printAndRightMove(indent, ch);
                        break;
                    }
                    case '}': {
                        indent = printAndLeftMove(indent, ch);
                        break;
                    }
                    case ',': {
                        this.formatResult += ch + "\r\n" + getBlankString(indent);
                        break;
                    }
                    default: {
                        this.formatResult += ch;
                        break;
                    }
                }
            }
            try {
                in.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public String getFormatResult(){
        return this.formatResult.trim();
    }

    public int printAndLeftMove(int indent, char ch) {
        this.formatResult += "\r\n";
        indent -= 4;
        this.formatResult += getBlankString(indent) + ch;
        return indent;
    }

    public int printAndRightMove(int indent, char ch) {
//        this.formatResult += "\r\n" + getBlankString(indent) + ch + "\r\n";
        this.formatResult += ch + getBlankString(indent) + "\r\n";
        indent += 4;
        this.formatResult += getBlankString(indent);
        return indent;
    }

    public String getBlankString(int length) {
        if (length <= 0) {
            return "";
        }
        String blankString = "";
        for (int i = 0; i < length; i++) {
            blankString += " ";
        }
        return blankString;
    }

}

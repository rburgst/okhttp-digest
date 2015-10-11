//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.burgstaller.okhttp.digest.fromhttpclient;


public interface HeaderValueParser {
    HeaderElement[] parseElements(CharArrayBuffer var1, ParserCursor var2) throws ParseException;

    HeaderElement parseHeaderElement(CharArrayBuffer var1, ParserCursor var2) throws ParseException;

    NameValuePair[] parseParameters(CharArrayBuffer var1, ParserCursor var2) throws ParseException;

    NameValuePair parseNameValuePair(CharArrayBuffer var1, ParserCursor var2) throws ParseException;
}

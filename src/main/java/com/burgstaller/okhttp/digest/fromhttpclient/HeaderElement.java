//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.burgstaller.okhttp.digest.fromhttpclient;


public interface HeaderElement {
    String getName();

    String getValue();

    NameValuePair[] getParameters();

    NameValuePair getParameterByName(String var1);

    int getParameterCount();

    NameValuePair getParameter(int var1);
}

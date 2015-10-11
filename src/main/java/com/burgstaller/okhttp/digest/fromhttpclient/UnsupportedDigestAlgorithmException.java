package com.burgstaller.okhttp.digest.fromhttpclient;

public class UnsupportedDigestAlgorithmException extends IllegalStateException {
    public UnsupportedDigestAlgorithmException(String detailMessage) {
        super(detailMessage);
    }
}

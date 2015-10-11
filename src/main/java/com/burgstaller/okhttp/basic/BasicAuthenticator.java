package com.burgstaller.okhttp.basic;

import com.burgstaller.okhttp.digest.Credentials;
import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import java.io.IOException;
import java.net.Proxy;

/**
 * Standard HTTP basic authenticator.
 */
public class BasicAuthenticator implements Authenticator {
    private final Credentials credentials;

    public BasicAuthenticator(Credentials credentials) {
        this.credentials = credentials;
    }

    @Override
    public Request authenticate(Proxy proxy, Response response) throws IOException {
        String authValue = com.squareup.okhttp.Credentials.basic(credentials.getUserName(), credentials.getPassword());
        return response.request().newBuilder()
                .header("Authorization", authValue)
                .build();
    }

    @Override
    public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
        return null;
    }
}

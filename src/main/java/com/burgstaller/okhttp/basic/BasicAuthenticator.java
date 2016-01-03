package com.burgstaller.okhttp.basic;

import com.burgstaller.okhttp.digest.Credentials;
import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

import java.io.IOException;

/**
 * Standard HTTP basic authenticator.
 */
public class BasicAuthenticator implements Authenticator {
    private final Credentials credentials;

    public BasicAuthenticator(Credentials credentials) {
        this.credentials = credentials;
    }

    @Override
    public Request authenticate(Route route, Response response) throws IOException {
        String authValue = okhttp3.Credentials.basic(credentials.getUserName(), credentials.getPassword());
        return response.request().newBuilder()
                .header("Authorization", authValue)
                .build();
    }
}

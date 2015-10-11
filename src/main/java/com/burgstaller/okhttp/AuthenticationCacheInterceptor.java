package com.burgstaller.okhttp;

import android.util.Log;

import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import java.io.IOException;
import java.util.Map;

/**
 * An HTTP Request interceptor that adds previous auth headers in to the same host. This enables the
 * client to reduce the number of 401 auth request/response cycles.
 */
public class AuthenticationCacheInterceptor implements Interceptor {
    private static final String TAG = "AuthInt";
    private final Map<String, String> authCache;

    public AuthenticationCacheInterceptor(Map<String, String> authCache) {
        this.authCache = authCache;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        String host = chain.request().uri().getHost();
        String authHeaderValue = authCache.get(host);
        final Request authRequest;
        if (authHeaderValue != null) {
            Log.d(TAG, "reusing auth from cache: " + authHeaderValue);
            authRequest = chain.request().newBuilder().header("Authorization", authHeaderValue).build();
        } else {
            authRequest = chain.request();
        }
        return chain.proceed(authRequest);
    }
}

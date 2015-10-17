package com.burgstaller.okhttp;

import android.util.Log;

import com.burgstaller.okhttp.digest.CachingAuthenticator;
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
    private final Map<String, CachingAuthenticator> authCache;

    public AuthenticationCacheInterceptor(Map<String, CachingAuthenticator> authCache) {
        this.authCache = authCache;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        final Request request = chain.request();
        String host = request.uri().getHost();
        CachingAuthenticator authenticator = authCache.get(host);
        Request authRequest = null;
        if (authenticator != null) {
            authRequest = authenticator.authenticateWithState(request);
            if (authRequest != null) {
                Log.d(TAG, "reusing auth from cache: " + authenticator);
            }
        }
        if (authRequest == null) {
            authRequest = request;
        }
        return chain.proceed(authRequest);
    }
}

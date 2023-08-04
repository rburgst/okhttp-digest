package com.burgstaller.okhttp;

import com.burgstaller.okhttp.digest.CachingAuthenticator;
import okhttp3.Connection;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import okhttp3.internal.platform.Platform;

import java.io.IOException;
import java.util.Map;

import static java.net.HttpURLConnection.HTTP_PROXY_AUTH;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;

public class AuthenticationCacheInterceptor implements Interceptor {
    private final Map<String, CachingAuthenticator> authCache;
    private final CacheKeyProvider cacheKeyProvider;

    public AuthenticationCacheInterceptor(Map<String, CachingAuthenticator> authCache, CacheKeyProvider cacheKeyProvider) {
        this.authCache = authCache;
        this.cacheKeyProvider = cacheKeyProvider;
    }

    public AuthenticationCacheInterceptor(Map<String, CachingAuthenticator> authCache) {
        this(authCache, new DefaultRequestCacheKeyProvider());
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        final Request request = chain.request();
        final String key;
        if (cacheKeyProvider.applyToProxy()) {
            key = cacheKeyProvider.getCachingKey(chain.connection().route().proxy());
        } else {
            key = cacheKeyProvider.getCachingKey(request);
        }
        CachingAuthenticator authenticator = authCache.get(key);
        Request authRequest = null;
        Connection connection = chain.connection();
        Route route = connection != null ? connection.route() : null;
        if (authenticator != null) {
            authRequest = authenticator.authenticateWithState(route, request);
        }
        if (authRequest == null) {
            authRequest = request;
        }
        Response response = chain.proceed(authRequest);

        // Cached response was used, but it produced unauthorized response (cache expired).
        int responseCode = response != null ? response.code() : 0;

        //authentication was against a web site
        if (authenticator != null && (!cacheKeyProvider.applyToProxy() && responseCode == HTTP_UNAUTHORIZED)) {
            // Remove cached authenticator and resend request
            if (authCache.remove(key) != null) {
                response.body().close();
                Platform.get().log("Cached authentication expired. Sending a new request.", Platform.INFO, null);
                // Force sending a new request without "Authorization" header
                response = chain.proceed(request);
            }
        }
        //authentication against a proxy
        if (authenticator != null && (cacheKeyProvider.applyToProxy() && responseCode == HTTP_PROXY_AUTH)) {
            authCache.remove(key);
            //interceptor at the proxy level is a Network Interceptor which does not permit to call proceed more than once.
            //in this case, we don't close the request and call chain.proceed(request) another time
        }

        return response;
    }

}

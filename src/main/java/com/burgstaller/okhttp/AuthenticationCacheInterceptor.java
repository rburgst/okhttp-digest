package com.burgstaller.okhttp;

import com.burgstaller.okhttp.digest.CachingAuthenticator;
import okhttp3.*;
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

        if (authenticator != null && (
                (cacheKeyProvider.applyToProxy() && responseCode == HTTP_PROXY_AUTH) ||
                        !cacheKeyProvider.applyToProxy() && responseCode == HTTP_UNAUTHORIZED)
        ) {
            response = removeCacheEntry(chain, key, request, response);
        }
        return response;
    }

    private Response removeCacheEntry(Chain chain, String key, Request request, Response response) throws IOException {
        // Remove cached authenticator and resend request
        if (authCache.remove(key) != null) {
            response.body().close();
            Platform.get().log("Cached authentication expired. Sending a new request.", Platform.INFO, null);
            // Force sending a new request without "Authorization" header
            //interceptor at the proxy level is a Network Interceptor which does not permit to call proceed more than once.
            if (!cacheKeyProvider.applyToProxy()) {
                response = chain.proceed(request);
            }
            return response;
        }
        return response;
    }
}
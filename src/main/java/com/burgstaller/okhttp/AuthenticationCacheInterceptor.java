package com.burgstaller.okhttp;

import com.burgstaller.okhttp.digest.CachingAuthenticator;

import java.io.IOException;
import java.util.Map;

import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.internal.platform.Platform;

import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;

/**
 * An HTTP Request interceptor that adds previous auth headers in to the same host. This enables the
 * client to reduce the number of 401 auth request/response cycles.
 */
public class AuthenticationCacheInterceptor implements Interceptor {
    private final Map<String, CachingAuthenticator> authCache;

    public AuthenticationCacheInterceptor(Map<String, CachingAuthenticator> authCache) {
        this.authCache = authCache;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        final Request request = chain.request();
        final HttpUrl url = request.url();
        final String key = CachingUtils.getCachingKey(url);
        CachingAuthenticator authenticator = authCache.get(key);
        Request authRequest = null;
        if (authenticator != null) {
            authRequest = authenticator.authenticateWithState(request);
        }
        if (authRequest == null) {
            authRequest = request;
        }
        Response response = chain.proceed(authRequest);

        // Cached response was used, but it produced unauthorized response (cache expired).
        if (authenticator != null && response != null && response.code() == HTTP_UNAUTHORIZED) {
            // Remove cached authenticator and resend request
            if (authCache.remove(key) != null) {
                response.body().close();
                Platform.get().log(Platform.INFO, "Cached authentication expired. Sending a new request.", null);
                // Force sending a new request without "Authorization" header
                response = chain.proceed(request);
            }
        }
        return response;
    }
}

package com.burgstaller.okhttp;

import com.burgstaller.okhttp.digest.CachingAuthenticator;

import okhttp3.Authenticator;
import okhttp3.HttpUrl;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

import java.io.IOException;
import java.util.Map;

/**
 * An authenticator decorator which saves the generated authentication headers for a specific host.
 * To be used in tandem with {@link AuthenticationCacheInterceptor}.
 * Depending on your use case you will probably need to use a {@link java.util.concurrent.ConcurrentHashMap}.
 */
public class CachingAuthenticatorDecorator implements Authenticator {
    private final Authenticator innerAuthenticator;
    private final Map<String, CachingAuthenticator> authCache;

    public CachingAuthenticatorDecorator(Authenticator innerAuthenticator, Map<String, CachingAuthenticator> authCache) {
        this.innerAuthenticator = innerAuthenticator;
        this.authCache = authCache;
    }

    @Override
    public Request authenticate(Route route, Response response) throws IOException {
        Request authenticated = innerAuthenticator.authenticate(route, response);
        if (authenticated != null) {
            String authorizationValue = authenticated.header("Authorization");
            if (authorizationValue != null && innerAuthenticator instanceof CachingAuthenticator) {
                final HttpUrl url = authenticated.url();
                final String key = CachingUtils.getCachingKey(url);
                authCache.put(key, (CachingAuthenticator) innerAuthenticator);
            }
        }
        return authenticated;
    }
}

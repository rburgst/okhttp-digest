package com.burgstaller.okhttp;

import java.io.IOException;
import java.util.Map;

import com.burgstaller.okhttp.digest.CachingAuthenticator;

import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

/**
 * An authenticator decorator which saves the generated authentication headers for a specific host.
 * To be used in tandem with {@link AuthenticationCacheInterceptor}.
 * Depending on your use case you will probably need to use a {@link java.util.concurrent.ConcurrentHashMap}.
 */
public class CachingAuthenticatorDecorator implements Authenticator {
    private final Authenticator innerAuthenticator;
    private final Map<String, CachingAuthenticator> authCache;
    private final CacheKeyProvider cacheKeyProvider;

    public CachingAuthenticatorDecorator(Authenticator innerAuthenticator, Map<String, CachingAuthenticator> authCache, CacheKeyProvider cacheKeyProvider) {
        this.innerAuthenticator = innerAuthenticator;
        this.authCache = authCache;
        this.cacheKeyProvider = cacheKeyProvider;
    }

    public CachingAuthenticatorDecorator(Authenticator innerAuthenticator, Map<String, CachingAuthenticator> authCache) {
        this(innerAuthenticator, authCache, new DefaultRequestCacheKeyProvider());
    }

    @Override
    public Request authenticate(Route route, Response response) throws IOException {
        Request authenticated = innerAuthenticator.authenticate(route, response);
        if (authenticated != null) {
            String authorizationValue = authenticated.header("Authorization");
            if (authorizationValue != null && innerAuthenticator instanceof CachingAuthenticator) {
                final String key = cacheKeyProvider.getCachingKey(authenticated);
                authCache.put(key, (CachingAuthenticator) innerAuthenticator);
            }
        }
        return authenticated;
    }
}

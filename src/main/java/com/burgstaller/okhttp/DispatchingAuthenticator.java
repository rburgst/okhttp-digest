package com.burgstaller.okhttp;

import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.Challenge;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import java.io.IOException;
import java.net.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A dispatching authenticator which can be used with multiple auth schemes.
 */
public class DispatchingAuthenticator implements CachingAuthenticator {
    private final Map<String, Authenticator> authenticatorRegistry;
    private final Map<String, CachingAuthenticator> cachingRegistry;

    public DispatchingAuthenticator(Map<String, Authenticator> registry) {
        authenticatorRegistry = registry;
        cachingRegistry = new HashMap<>();
        for (Map.Entry<String, Authenticator> entry : authenticatorRegistry.entrySet()) {
            if (entry.getValue() instanceof CachingAuthenticator) {
                cachingRegistry.put(entry.getKey(), (CachingAuthenticator) entry.getValue());
            }
        }
    }

    @Override
    public Request authenticate(Proxy proxy, Response response) throws IOException {
        List<Challenge> challenges = response.challenges();
        if (!challenges.isEmpty()) {
            for (Challenge challenge : challenges) {
                Authenticator authenticator = authenticatorRegistry.get(challenge.getScheme());
                if (authenticator != null) {
                    return authenticator.authenticate(proxy, response);
                }
            }
        }
        throw new IllegalArgumentException("unsupported auth scheme " + challenges);
    }

    @Override
    public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
        return null;
    }

    @Override
    public Request authenticateWithState(Request request) throws IOException {
        for (Map.Entry<String, CachingAuthenticator> authenticatorEntry : cachingRegistry.entrySet()) {
            final Request authRequest = authenticatorEntry.getValue().authenticateWithState(request);
            if (authRequest != null) {
                return authRequest;
            }
        }
        return null;
    }

    public static final class Builder {
        Map<String, Authenticator> registry = new HashMap<>();

        public Builder with(String scheme, Authenticator authenticator) {
            registry.put(scheme, authenticator);
            return this;
        }

        public DispatchingAuthenticator build() {
            return new DispatchingAuthenticator(registry);
        }
    }
}

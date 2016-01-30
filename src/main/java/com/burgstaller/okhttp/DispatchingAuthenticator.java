package com.burgstaller.okhttp;

import com.burgstaller.okhttp.digest.CachingAuthenticator;

import okhttp3.Authenticator;
import okhttp3.Challenge;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

import java.io.IOException;
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
    public Request authenticate(Route route, Response response) throws IOException {
        List<Challenge> challenges = response.challenges();
        if (!challenges.isEmpty()) {
            for (Challenge challenge : challenges) {
                final String scheme = challenge.scheme();
                Authenticator authenticator = null;
                if (scheme != null) {
                    authenticator = authenticatorRegistry.get(scheme.toLowerCase());
                }
                if (authenticator != null) {
                    return authenticator.authenticate(route, response);
                }
            }
        }
        throw new IllegalArgumentException("unsupported auth scheme " + challenges);
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

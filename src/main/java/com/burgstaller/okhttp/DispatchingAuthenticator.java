package com.burgstaller.okhttp;

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
public class DispatchingAuthenticator implements Authenticator {
    private final Map<String, Authenticator> authenticatorRegistry;

    public DispatchingAuthenticator(Map<String, Authenticator> registry) {
        authenticatorRegistry = registry;
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

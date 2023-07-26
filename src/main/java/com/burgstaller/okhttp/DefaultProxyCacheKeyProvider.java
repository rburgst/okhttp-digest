package com.burgstaller.okhttp;

import java.net.Proxy;

/**
 * The default version of the cache key provider, which simply calls the {@link java.net.Proxy#toString()} method to generate key.
 */
public final class DefaultProxyCacheKeyProvider implements CacheKeyProvider<Proxy> {
    @Override
    public boolean applyToProxy() {
        return true;
    }

    /**
     *
     * @param proxy {@link java.net.Proxy} used to get the cache key.
     * @return the cache key.
     */
    @Override
    public String getCachingKey(Proxy proxy) {
        return proxy != null ? proxy.toString() : null;
    }
}

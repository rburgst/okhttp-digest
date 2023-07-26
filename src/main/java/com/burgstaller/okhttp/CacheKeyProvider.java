package com.burgstaller.okhttp;

/**
 * Provides the caching key for the given request or {@link java.net.Proxy}. Can be used to share passwords accross multiple subdomains.
 * @see java.net.Proxy
 */
public interface CacheKeyProvider<T> {

    /**
     *
     * @return true if the key is forged from a {@link java.net.Proxy} Object.
     */
    boolean applyToProxy();
    /**
     * Provides the caching key for the given request or {@link java.net.Proxy}. Can be used to share passwords accross multiple subdomains.
     *
     * @param request the http request, or a {@link java.net.Proxy} if the applyToProxy method returns true.
     * @return the cache key.
     */
    String getCachingKey(T request);
}


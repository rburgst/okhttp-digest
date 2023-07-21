package com.burgstaller.okhttp;

public interface CacheKeyProvider<T> {

    /**
     *
     * @return true if the key is forged from a Proxy Object.
     */
    boolean applyToProxy();
    /**
     * Provides the caching key for the given request. Can be used to share passwords accross multiple subdomains.
     *
     * @param request the http request.
     * @return the cache key.
     */
    String getCachingKey(T request);
}


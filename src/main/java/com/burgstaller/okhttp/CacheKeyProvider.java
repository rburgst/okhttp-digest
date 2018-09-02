package com.burgstaller.okhttp;

import okhttp3.Request;

/**
 * Provides the caching key for the given request. Can be used to share passwords accross multiple subdomains.
 */
public interface CacheKeyProvider {
    /**
     * Provides the caching key for the given request. Can be used to share passwords accross multiple subdomains.
     *
     * @param request the http request.
     * @return the cache key.
     */
    String getCachingKey(Request request);
}

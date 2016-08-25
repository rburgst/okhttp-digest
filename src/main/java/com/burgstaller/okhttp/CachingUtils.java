package com.burgstaller.okhttp;

import okhttp3.HttpUrl;

public final class CachingUtils {

    /**
     * Get key to be used for storing cached auth responses, e.g.
     * http:myhost.com:8080
     */
    public static String getCachingKey(HttpUrl url) {
        if (url == null)
            return null;
        return url.scheme() + ":" + url.host() + ":" + url.port();
    }

}

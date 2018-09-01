package com.burgstaller.okhttp

import okhttp3.HttpUrl

object CachingUtils {
  /**
   * Get key to be used for storing cached auth responses, e.g.
   * http:myhost.com:8080
   */
  fun defaultCacheKey(url: HttpUrl): String {
    return "${url.scheme()}:${url.host()}:${url.port()}"
  }
}

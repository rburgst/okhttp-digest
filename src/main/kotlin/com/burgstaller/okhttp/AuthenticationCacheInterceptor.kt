package com.burgstaller.okhttp

import com.burgstaller.okhttp.digest.CachingAuthenticator
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import okhttp3.internal.platform.Platform
import java.io.IOException
import java.net.HttpURLConnection.HTTP_PROXY_AUTH
import java.net.HttpURLConnection.HTTP_UNAUTHORIZED

/**
 * An HTTP Request interceptor that adds previous auth headers in to the same host. This enables the
 * client to reduce the number of 401 auth request/response cycles.
 */
class AuthenticationCacheInterceptor(private val authCache: MutableMap<String, CachingAuthenticator>) : Interceptor {

  @Throws(IOException::class)
  override fun intercept(chain: Interceptor.Chain): Response? {
    val request = chain.request()
    val url = request.url()
    val key = CachingUtils.defaultCacheKey(url)
    val authenticator = authCache[key]
    var authRequest: Request? = null
    val connection = chain.connection()
    val route = connection?.route()
    if (authenticator != null) {
      authRequest = authenticator.authenticateWithState(route, request)
    }
    if (authRequest == null) {
      authRequest = request
    }
    var response: Response? = chain.proceed(authRequest)

    // Cached response was used, but it produced unauthorized response (cache expired).
    val responseCode = response?.code() ?: 0
    if (authenticator != null && (responseCode == HTTP_UNAUTHORIZED || responseCode == HTTP_PROXY_AUTH)) {
      // Remove cached authenticator and resend request
      if (authCache.remove(key) != null) {
        response!!.body()!!.close()
        Platform.get().log(Platform.INFO, "Cached authentication expired. Sending a new request.", null)
        // Force sending a new request without "Authorization" header
        response = chain.proceed(request)
      }
    }
    return response
  }
}

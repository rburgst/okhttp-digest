package com.burgstaller.okhttp.basic

import com.burgstaller.okhttp.digest.CachingAuthenticator
import com.burgstaller.okhttp.digest.Credentials
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route
import okhttp3.internal.platform.Platform
import java.net.HttpURLConnection.HTTP_PROXY_AUTH

/**
 * Standard HTTP basic authenticator.
 */
open class BasicAuthenticator(private val credentials: Credentials) : CachingAuthenticator {
  private var proxy: Boolean = false

  override fun authenticate(route: Route?, response: Response): Request? {
    val request = response.request()
    proxy = response.code() == HTTP_PROXY_AUTH
    return authFromRequest(request)
  }

  private fun authFromRequest(request: Request): Request? {
    // prevent infinite loops when the password is wrong
    val header = if (proxy) "Proxy-Authorization" else "Authorization"

    val authorizationHeader = request.header(header)
    if (authorizationHeader != null && authorizationHeader.startsWith("Basic")) {
      Platform.get().log(Platform.WARN, "previous basic authentication failed, returning null", null)
      return null
    }
    val authValue = okhttp3.Credentials.basic(credentials.userName, credentials.password)
    return request.newBuilder()
            .header(header, authValue)
            .build()
  }

  override fun authenticateWithState(route: Route?, request: Request): Request? {
    return authFromRequest(request)
  }
}

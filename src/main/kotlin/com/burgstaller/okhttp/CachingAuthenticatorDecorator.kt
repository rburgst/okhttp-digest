package com.burgstaller.okhttp

import com.burgstaller.okhttp.digest.CachingAuthenticator
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

/**
 * An authenticator decorator which saves the generated authentication headers for a specific host.
 * To be used in tandem with [AuthenticationCacheInterceptor].
 * Depending on your use case you will probably need to use a [java.util.concurrent.ConcurrentHashMap].
 */
class CachingAuthenticatorDecorator(private val innerAuthenticator: Authenticator, private val authCache: MutableMap<String, CachingAuthenticator>) : Authenticator {
  override fun authenticate(route: Route?, response: Response): Request? {
    val authenticated = innerAuthenticator.authenticate(route, response)
    if (authenticated != null) {
      val authorizationValue = authenticated.header("Authorization")
      if (authorizationValue != null && innerAuthenticator is CachingAuthenticator) {
        val url = authenticated.url()
        val key = CachingUtils.defaultCacheKey(url)
        authCache[key] = innerAuthenticator
      }
    }
    return authenticated
  }
}

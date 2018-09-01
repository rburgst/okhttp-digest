package com.burgstaller.okhttp

import com.burgstaller.okhttp.digest.CachingAuthenticator
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route
import java.util.LinkedHashMap
import java.util.Locale

/**
 * A dispatching authenticator which can be used with multiple auth schemes.
 */
class DispatchingAuthenticator private constructor(private val authenticatorRegistry: Map<String, Authenticator>) : CachingAuthenticator {
  private val cachingRegistry: MutableMap<String, CachingAuthenticator>

  init {
    cachingRegistry = LinkedHashMap()
    for ((key, value) in authenticatorRegistry) {
      if (value is CachingAuthenticator) {
        cachingRegistry[key] = value
      }
    }
  }

  override fun authenticate(route: Route?, response: Response): Request? {
    val challenges = response.challenges()
    if (!challenges.isEmpty()) {
      for (challenge in challenges) {
        val scheme = challenge.scheme()
        var authenticator: Authenticator? = null
        if (scheme != null) {
          authenticator = authenticatorRegistry[scheme.toLowerCase(Locale.getDefault())]
        }
        if (authenticator != null) {
          return authenticator.authenticate(route, response)
        }
      }
    }
    throw IllegalArgumentException("unsupported auth scheme $challenges")
  }

  override fun authenticateWithState(route: Route?, request: Request): Request? {
    for ((_, value) in cachingRegistry) {
      val authRequest = value.authenticateWithState(route, request)
      if (authRequest != null) {
        return authRequest
      }
    }
    return null
  }

  class Builder {
    private var registry: MutableMap<String, Authenticator> = LinkedHashMap()

    fun with(scheme: String, authenticator: Authenticator): Builder {
      registry[scheme.toLowerCase(Locale.getDefault())] = authenticator
      return this
    }

    fun build(): DispatchingAuthenticator {
      return DispatchingAuthenticator(registry)
    }
  }
}


/*
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.burgstaller.okhttp.digest

import com.burgstaller.okhttp.digest.fromhttpclient.BasicHeaderValueFormatter
import com.burgstaller.okhttp.digest.fromhttpclient.BasicHeaderValueParser
import com.burgstaller.okhttp.digest.fromhttpclient.BasicNameValuePair
import com.burgstaller.okhttp.digest.fromhttpclient.CharArrayBuffer
import com.burgstaller.okhttp.digest.fromhttpclient.HttpEntityDigester
import com.burgstaller.okhttp.digest.fromhttpclient.NameValuePair
import com.burgstaller.okhttp.digest.fromhttpclient.ParserCursor
import com.burgstaller.okhttp.digest.fromhttpclient.UnsupportedDigestAlgorithmException

import java.io.IOException
import java.io.UnsupportedEncodingException
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.ArrayList
import java.util.Collections
import java.util.Formatter
import java.util.HashMap
import java.util.HashSet
import java.util.Locale
import java.util.StringTokenizer
import java.util.concurrent.atomic.AtomicReference

import okhttp3.Headers
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route
import okhttp3.internal.http.RequestLine
import okhttp3.internal.platform.Platform

@ExperimentalUnsignedTypes
/**
 * Digest authenticator which is more or less the same code ripped out of Apache HTTP Client 4.3.1.
 */
open class DigestAuthenticator(private val credentials: Credentials) : CachingAuthenticator {

  private val parametersRef = AtomicReference<Map<String, String>>()
  /**
   * Returns the charset used for the credentials.
   *
   * @return the credentials charset
   */
  private val credentialsCharset: Charset = Charset.forName("ASCII")
  private var lastNonce: String? = null
  private var nounceCount: Long = 0
  private var cnonce: String? = null
  private var a1: String? = null
  private var a2: String? = null
  private var isProxy: Boolean = false

  private fun parseChallenge(
          buffer: String, pos: Int, len: Int, params: MutableMap<String, String>) {

    val parser = BasicHeaderValueParser.INSTANCE
    val cursor = ParserCursor(pos, buffer.length)
    val buf = CharArrayBuffer(len)
    buf.append(buffer)

    val elements = parser.parseElements(buf, cursor)
    if (elements.isEmpty()) {
      throw IllegalArgumentException("Authentication challenge is empty")
    }

    for (element in elements) {
      params[element.name] = element.value
    }
  }

  @Synchronized
  @Throws(IOException::class)
  override fun authenticate(route: Route?, response: Response): Request? {
    val header = findDigestHeader(response.headers(), getHeaderName(response.code()))
    val parameters = HashMap<String, String>()
    parseChallenge(header, 7, header.length - 7, parameters)
    // first copy all request headers to our params array
    copyHeaderMap(response.headers(), parameters)
    // save these parameters so future requests don't need the challenge response every time
    parametersRef.set(Collections.unmodifiableMap(parameters))

    // sanity check for issue #22
    if (parameters["nonce"] == null) {
      throw IllegalArgumentException("missing nonce in challenge header: $header")
    }

    return authenticateWithState(route, response.request(), parameters)
  }

  private fun getHeaderName(httpStatus: Int): String {
    if (httpStatus == 401) {
      isProxy = false
      return WWW_AUTH
    }
    if (httpStatus == 407) {
      isProxy = true
      return PROXY_AUTH
    }
    return ""
  }

  private fun findDigestHeader(headers: Headers, name: String): String {
    val authHeaders = headers.values(name)
    for (header in authHeaders) {
      if (header.startsWith("Digest")) {
        return header
      }
    }
    throw IllegalArgumentException("unsupported auth scheme: $authHeaders")
  }

  @Throws(IOException::class)
  override fun authenticateWithState(route: Route?, request: Request): Request? {
    // make sure we don't modify the values in shared parametersRef instance
    val ref = parametersRef.get()
    val parameters = if (ref == null)
      HashMap()
    else
      HashMap(ref)
    return authenticateWithState(route, request, parameters)
  }

  @Throws(IOException::class)
  private fun authenticateWithState(route: Route?, request: Request, parameters: MutableMap<String, String>): Request? {
    val realm = parameters["realm"]
            ?: // missing realm, this would mean that the authenticator is not initialized for this
            // request. (e.g. if you configured the DispatchingAuthenticator.
            return null
    val nonce = parameters["nonce"] ?: throw IllegalArgumentException("missing nonce in challenge")
    val stale = parameters["stale"]
    val isStale = "true".equals(stale, ignoreCase = true)

    if (havePreviousDigestAuthorizationAndShouldAbort(request, nonce, isStale)) {
      // prevent infinite loops when the password is wrong
      Platform.get().log(Platform.WARN, "previous digest authentication with same nonce failed, returning null", null)
      return null
    }

    // Add method name and request-URI to the parameter map
    if (route == null || !route.requiresTunnel()) {
      val method = request.method()
      val uri = RequestLine.requestPath(request.url())
      parameters["methodname"] = method
      parameters["uri"] = uri
    } else {
      val method = "CONNECT"
      val uri = request.url().host() + ':'.toString() + request.url().port()
      parameters["methodname"] = method
      parameters["uri"] = uri
    }

    val charset = parameters["charset"]
    if (charset == null) {
      val credentialsCharset = getCredentialsCharset(request)
      parameters["charset"] = credentialsCharset
    }
    val digestHeader = createDigestHeader(credentials, request, parameters)
    return request.newBuilder()
            .header(digestHeader.name, digestHeader.value)
            .build()
  }

  /**
   * Checks if the previous request had a digest authorization and its nonce matches to the
   * current server nonce. If that is the case, then we would simply attempt the same authentication
   * again and would fail again and again, ...
   *
   * @param request the previous request
   * @param nonce   the current server nonce.
   * @param isStale when `true` then the server told us that the nonce was stale.
   * @return `true` in case the previous request already was authenticating to the current
   * server nonce.
   */
  private fun havePreviousDigestAuthorizationAndShouldAbort(request: Request, nonce: String, isStale: Boolean): Boolean {
    val headerKey: String
    headerKey = if (isProxy) {
      PROXY_AUTH_RESP
    } else {
      WWW_AUTH_RESP
    }
    val previousAuthorizationHeader = request.header(headerKey)

    return if (previousAuthorizationHeader != null && previousAuthorizationHeader.startsWith("Digest")) {
      // only retry when the previous auth was stale
      !isStale
    } else false
  }

  private fun copyHeaderMap(headers: Headers, dest: MutableMap<String, String>) {
    for (i in 0 until headers.size()) {
      dest[headers.name(i)] = headers.value(i)
    }
  }

  /**
   * Creates digest-response header as defined in RFC2617.
   *
   * @param credentials User credentials
   * @return The digest-response as String.
   */
  //    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("LSC_LITERAL_STRING_COMPARISON")
  @Synchronized
  @Throws(DigestAuthenticator.AuthenticationException::class)
  private fun createDigestHeader(
          credentials: Credentials,
          request: Request,
          parameters: Map<String, String>): NameValuePair {
    val uri = parameters["uri"]
    val realm = parameters["realm"]
    val nonce = parameters["nonce"]
    val opaque = parameters["opaque"]
    val method = parameters["methodname"]
    var algorithm: String? = parameters["algorithm"]
    // If an algorithm is not specified, default to MD5.
    if (algorithm == null) {
      algorithm = "MD5"
    }

    val qopset = HashSet<String>(8)
    var qop = QOP_UNKNOWN
    val qoplist = parameters["qop"]
    if (qoplist != null) {
      val tok = StringTokenizer(qoplist, ",")
      while (tok.hasMoreTokens()) {
        val variant = tok.nextToken().trim { it <= ' ' }
        qopset.add(variant.toLowerCase(Locale.US))
      }
      if (request.body() != null && qopset.contains("auth-int")) {
        qop = QOP_AUTH_INT
      } else if (qopset.contains("auth")) {
        qop = QOP_AUTH
      }
    } else {
      qop = QOP_MISSING
    }

    if (qop == QOP_UNKNOWN) {
      throw AuthenticationException("None of the qop methods is supported: " + qoplist!!)
    }

    var charset: String? = parameters["charset"]
    if (charset == null) {
      charset = "ISO-8859-1"
    }

    var digAlg: String = algorithm
    if ("MD5-sess".equals(digAlg, ignoreCase = true)) {
      digAlg = "MD5"
    }

    val digester: MessageDigest
    try {
      digester = createMessageDigest(digAlg)
    } catch (ex: UnsupportedDigestAlgorithmException) {
      throw AuthenticationException("Unsuppported digest algorithm: $digAlg", ex)
    }

    val uname = credentials.userName
    val pwd = credentials.password

    if (nonce == this.lastNonce) {
      nounceCount++
    } else {
      nounceCount = 1
      cnonce = null
      lastNonce = nonce
    }
    val sb = StringBuilder(256)
    val formatter = Formatter(sb, Locale.US)
    formatter.format("%08x", nounceCount)
    formatter.close()
    val nc = sb.toString()

    if (cnonce == null) {
      cnonce = createCnonce()
    }

    a1 = null
    a2 = null
    // 3.2.2.2: Calculating digest
    if ("MD5-sess".equals(algorithm, ignoreCase = true)) {
      // H( unq(username-value) ":" unq(realm-value) ":" passwd )
      //      ":" unq(nonce-value)
      //      ":" unq(cnonce-value)

      // calculated one per session
      sb.setLength(0)
      sb.append(uname).append(':').append(realm).append(':').append(pwd)
      val checksum = encode(digester.digest(getBytes(sb.toString(), charset)).toUByteArray())
      sb.setLength(0)
      sb.append(checksum).append(':').append(nonce).append(':').append(cnonce)
      a1 = sb.toString()
    } else {
      // unq(username-value) ":" unq(realm-value) ":" passwd
      sb.setLength(0)
      sb.append(uname).append(':').append(realm).append(':').append(pwd)
      a1 = sb.toString()
    }

    val hasha1 = encode(digester.digest(getBytes(a1!!, charset)).toUByteArray())

    if (qop == QOP_AUTH) {
      // Method ":" digest-uri-value
      a2 = method + ':'.toString() + uri
    } else if (qop == QOP_AUTH_INT) {
      // Method ":" digest-uri-value ":" H(entity-body)
      val entity = request.body()
      if (entity != null) {
        // If the entity is not repeatable, try falling back onto QOP_AUTH
        if (qopset.contains("auth")) {
          qop = QOP_AUTH
          a2 = method + ':'.toString() + uri
        } else {
          throw AuthenticationException("Qop auth-int cannot be used with " + "a non-repeatable entity")
        }
      } else {
        // code straight from
        // https://github.com/apache/httpclient/blob/4.3.x/httpclient/src/main/java/org/apache/http/impl/auth/DigestScheme.java#L363
        // not sure if this will actually work with an empty body.
        val entityDigester = HttpEntityDigester(digester)
        try {
          entityDigester.close()
        } catch (ex: IOException) {
          throw AuthenticationException("I/O error reading entity content", ex)
        }

        a2 = method + ':'.toString() + uri + ':'.toString() + encode(entityDigester.digest.toUByteArray())
      }
    } else {
      a2 = method + ':'.toString() + uri
    }

    val hasha2 = encode(digester.digest(getBytes(a2!!, charset)).toUByteArray())

    // 3.2.2.1

    val digestValue: String
    digestValue = if (qop == QOP_MISSING) {
      sb.setLength(0)
      sb.append(hasha1).append(':').append(nonce).append(':').append(hasha2)
      sb.toString()
    } else {
      sb.setLength(0)
      sb.append(hasha1).append(':').append(nonce).append(':').append(nc).append(':')
              .append(cnonce).append(':').append(if (qop == QOP_AUTH_INT) "auth-int" else "auth")
              .append(':').append(hasha2)
      sb.toString()
    }

    val digest = encode(digester.digest(getAsciiBytes(digestValue)).toUByteArray())

    val buffer = StringBuilder(128)
    val headerKey: String
    headerKey = if (isProxy) {
      PROXY_AUTH_RESP
    } else {
      WWW_AUTH_RESP
    }
    buffer.append("Digest ")

    val params = ArrayList<NameValuePair>(20)
    params.add(BasicNameValuePair("username", uname))
    params.add(BasicNameValuePair("realm", realm))
    params.add(BasicNameValuePair("nonce", nonce))
    params.add(BasicNameValuePair("uri", uri))
    params.add(BasicNameValuePair("response", digest))

    if (qop != QOP_MISSING) {
      params.add(BasicNameValuePair("qop", if (qop == QOP_AUTH_INT) "auth-int" else "auth"))
      params.add(BasicNameValuePair("nc", nc))
      params.add(BasicNameValuePair("cnonce", cnonce))
    }
    // algorithm cannot be null here
    params.add(BasicNameValuePair("algorithm", algorithm))
    if (opaque != null) {
      params.add(BasicNameValuePair("opaque", opaque))
    }

    for (i in params.indices) {
      val param = params[i]
      if (i > 0) {
        buffer.append(", ")
      }
      val name = param.name
      val noQuotes = ("nc" == name || "qop" == name
              || "algorithm" == name)
      BasicHeaderValueFormatter.DEFAULT.formatNameValuePair(buffer, param, !noQuotes)
    }
    return BasicNameValuePair(headerKey, buffer.toString())
  }

  private fun getCredentialsCharset(request: Request): String {
    return request.header(CREDENTIAL_CHARSET) ?: credentialsCharset.name()
  }

  private fun getBytes(s: String, charset: String): ByteArray {
    try {
      return s.toByteArray(charset(charset))
    } catch (e: UnsupportedEncodingException) {
      // try again with default encoding
      return s.toByteArray()
    }

  }

  private class AuthenticationException : IllegalStateException {
    constructor(s: String) : super(s)

    constructor(message: String, ex: Exception) : super(message, ex)
  }

  @ExperimentalUnsignedTypes
  companion object {

    const val PROXY_AUTH = "Proxy-Authenticate"
    const val PROXY_AUTH_RESP = "Proxy-Authorization"
    const val WWW_AUTH = "WWW-Authenticate"
    const val WWW_AUTH_RESP = "Authorization"

    private const val CREDENTIAL_CHARSET = "http.auth.credential-charset"
    private const val QOP_UNKNOWN = -1
    private const val QOP_MISSING = 0
    private const val QOP_AUTH_INT = 1
    private const val QOP_AUTH = 2

    /**
     * Hex values used when creating 32 character long digest in HTTP DigestScheme
     * in case of authentication.
     *
     * @see .encode
     */
    private val HEXADECIMAL = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')

    private fun createMessageDigest(
            digAlg: String): MessageDigest {
      try {
        return MessageDigest.getInstance(digAlg)
      } catch (e: Exception) {
        throw IllegalArgumentException(
                "Unsupported algorithm in HTTP Digest authentication: $digAlg", e)
      }

    }

    /**
     * Creates a random cnonce value based on the current time.
     *
     * @return The cnonce value as String.
     */
    fun createCnonce(): String {
      val rnd = SecureRandom()
      val tmp = ByteArray(8)
      rnd.nextBytes(tmp)
      return encode(tmp.toUByteArray())
    }


    /**
     * Encodes the 128 bit (16 bytes) MD5 digest into a 32 characters long
     * <CODE>String</CODE> according to RFC 2617.
     *
     * @param binaryData array containing the digest
     * @return encoded MD5, or <CODE>null</CODE> if encoding failed
     */
    internal fun encode(binaryData: UByteArray): String {
      val n = binaryData.size
      val buffer = CharArray(n * 2)
      for (i in 0 until n) {
        val low = binaryData[i].toInt() and 0x0f
        val high = binaryData[i].toInt() and 0xf0 shr 4
        buffer[i * 2] = HEXADECIMAL[high]
        buffer[i * 2 + 1] = HEXADECIMAL[low]
      }

      return String(buffer)
    }

    fun getAsciiBytes(data: String?): ByteArray {
      return if (data == null) {
        throw IllegalArgumentException("Parameter may not be null")
      } else {
        try {
          data.toByteArray(charset("US-ASCII"))
        } catch (e: UnsupportedEncodingException) {
          throw Error("HttpClient requires ASCII support", e)
        }

      }
    }
  }
}
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

package com.burgstaller.okhttp.digest;

import com.burgstaller.okhttp.digest.fromhttpclient.BasicHeaderValueFormatter;
import com.burgstaller.okhttp.digest.fromhttpclient.BasicHeaderValueParser;
import com.burgstaller.okhttp.digest.fromhttpclient.BasicNameValuePair;
import com.burgstaller.okhttp.digest.fromhttpclient.CharArrayBuffer;
import com.burgstaller.okhttp.digest.fromhttpclient.HeaderElement;
import com.burgstaller.okhttp.digest.fromhttpclient.HttpEntityDigester;
import com.burgstaller.okhttp.digest.fromhttpclient.NameValuePair;
import com.burgstaller.okhttp.digest.fromhttpclient.ParserCursor;
import com.burgstaller.okhttp.digest.fromhttpclient.UnsupportedDigestAlgorithmException;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.Route;
import okhttp3.internal.platform.Platform;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Digest authenticator which is more or less the same code ripped out of Apache
 * HTTP Client 4.3.1.
 */
public class DigestAuthenticator implements CachingAuthenticator {

    public static final String PROXY_AUTH = "Proxy-Authenticate";
    public static final String PROXY_AUTH_RESP = "Proxy-Authorization";
    public static final String WWW_AUTH = "WWW-Authenticate";
    public static final String WWW_AUTH_RESP = "Authorization";

    private static final String CREDENTIAL_CHARSET = "http.auth.credential-charset";
    private static final int QOP_UNKNOWN = -1;
    private static final int QOP_MISSING = 0;
    private static final int QOP_AUTH_INT = 1;
    private static final int QOP_AUTH = 2;
    /**
     * Hexa values used when creating 32 character long digest in HTTP DigestScheme
     * in case of authentication.
     *
     * @see #encode(byte[])
     */
    private static final char[] HEXADECIMAL = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
            'e', 'f'};
    private final Random random;
    private final Credentials credentials;
    private final AtomicReference<Map<String, String>> parametersRef = new AtomicReference<>();
    private final Charset credentialsCharset;
    private String lastNonce;
    private long nounceCount;
    private String cnonce;
    private String a1;
    private String a2;
    private boolean proxy;

    public DigestAuthenticator(Credentials credentials) {
        this.credentials = credentials;
        this.credentialsCharset = StandardCharsets.US_ASCII;
        this.random = new SecureRandom();
    }

    public DigestAuthenticator(Credentials credentials, Charset credentialsCharset) {
        this.credentials = credentials;
        this.credentialsCharset = credentialsCharset;
        this.random = new SecureRandom();
    }

    public DigestAuthenticator(Credentials credentials, Charset credentialsCharset, Random random) {
        this.credentials = credentials;
        this.credentialsCharset = credentialsCharset;
        this.random = random;
    }

    private MessageDigest createMessageDigest(final String digAlg) {
        try {
            return MessageDigest.getInstance(digAlg);
        } catch (final Exception e) {
            throw new IllegalArgumentException("Unsupported algorithm in HTTP Digest authentication: " + digAlg, e);
        }
    }

    /**
     * Creates a random cnonce value based on the current time.
     *
     * @return The cnonce value as String.
     */
    public String createCnonce() {
        final byte[] tmp = new byte[8];
        random.nextBytes(tmp);
        return encode(tmp);
    }

    /**
     * Encodes the 128 bit (16 bytes) MD5 digest into a 32 characters long
     * <CODE>String</CODE> according to RFC 2617.
     *
     * @param binaryData array containing the digest
     * @return encoded MD5, or <CODE>null</CODE> if encoding failed
     */
    private String encode(final byte[] binaryData) {
        final int n = binaryData.length;
        final char[] buffer = new char[n * 2];
        for (int i = 0; i < n; i++) {
            final int low = (binaryData[i] & 0x0f);
            final int high = ((binaryData[i] & 0xf0) >> 4);
            buffer[i * 2] = HEXADECIMAL[high];
            buffer[(i * 2) + 1] = HEXADECIMAL[low];
        }

        return new String(buffer);
    }

    protected void parseChallenge(final String buffer, int pos, int len, Map<String, String> params) {

        BasicHeaderValueParser parser = BasicHeaderValueParser.INSTANCE;
        ParserCursor cursor = new ParserCursor(pos, buffer.length());
        CharArrayBuffer buf = new CharArrayBuffer(len);
        buf.append(buffer);

        HeaderElement[] elements = parser.parseElements(buf, cursor);
        if (elements.length == 0) {
            throw new IllegalArgumentException("Authentication challenge is empty");
        }

        for (HeaderElement element : elements) {
            params.put(element.getName(), element.getValue());
        }
    }

    @Override
    public synchronized Request authenticate(Route route, Response response) throws IOException {
        String header = findDigestHeader(response.headers(), getHeaderName(response.code()));
        if (header == null) {
            return null;
        }
        // note that it might be that at the time where we set the parametersRef we already have someone in parallel
        // trying to access it, therefore we use a concurrent map to avoid concurrent modification exceptions
        // if 2 requests happen at the same time while we are still negotiating the nonce etc, we will do the
        // negotiation handshake multiple times, well this cannot be helped really. One of the contestants will win
        Map<String, String> parameters = new ConcurrentHashMap<>();
        parseChallenge(header, 7, header.length() - 7, parameters);
        // first copy all request headers to our params array
        copyHeaderMap(response.headers(), parameters);
        // save these parameters so future requests don't need the challenge response
        // every time
        parametersRef.set(Collections.unmodifiableMap(parameters));

        // sanity check for issue #22
        if (parameters.get("nonce") == null) {
            throw new IOException("missing nonce in challenge header: " + header);
        }

        Request request = authenticateWithState(route, response.request(), parameters);
        List<String> cookies = response.headers().values("Set-Cookie");
        if (request != null && !cookies.isEmpty()) {
            String cookie = cookies.get(0).split(";")[0];
            return request.newBuilder().header("Cookie", cookie).build();
        }
        return request;
    }

    private String getHeaderName(int httpStatus) {
        if (httpStatus == 401) {
            setProxy(false);
            return WWW_AUTH;
        }
        if (httpStatus == 407) {
            setProxy(true);
            return PROXY_AUTH;
        }
        return "";
    }

    private String findDigestHeader(Headers headers, String name) throws IOException {
        final List<String> authHeaders = headers.values(name);
        for (String header : authHeaders) {
            if (header.startsWith("Digest")) {
                return header;
            }
        }
        // note that we dont support preemtive auth for now
        if (authHeaders.contains("OkHttp-Preemptive")) {
            return null;
        }
        throw new IOException("unsupported auth scheme: " + authHeaders);
    }

    @Override
    public Request authenticateWithState(Route route, Request request) throws IOException {
        // make sure we don't modify the values in shared parametersRef instance
        Map<String, String> ref = parametersRef.get();
        Map<String, String> parameters = ref == null ? new ConcurrentHashMap<>() : new ConcurrentHashMap<>(ref);
        return authenticateWithState(route, request, parameters);
    }

    private Request authenticateWithState(Route route, Request request, Map<String, String> parameters)
            throws IOException {
        final String realm = parameters.get("realm");
        if (realm == null) {
            // missing realm, this would mean that the authenticator is not initialized for
            // this request. (e.g. if you configured the DispatchingAuthenticator).
            return null;
        }
        final String nonce = parameters.get("nonce");
        if (nonce == null) {
            throw new IOException("missing nonce in challenge");
        }
        String stale = parameters.get("stale");
        boolean isStale = "true".equalsIgnoreCase(stale);

        if (havePreviousDigestAuthorizationAndShouldAbort(request, nonce, isStale)) {
            // prevent infinite loops when the password is wrong
            Platform.get().log("Previous digest authentication with same nonce failed, returning null", Platform.WARN,
                    null);
            return null;
        }

        // Add method name and request-URI to the parameter map
        if (parameters.get("proxy-authenticate") != null) {
            final String method = "CONNECT";
            final String uri = request.url().host() + ':' + request.url().port();
            parameters.put("methodname", method);
            parameters.put("uri", uri);
        } else {
            final String method = request.method();
            final String uri = this.requestPath(request.url());
            parameters.put("methodname", method);
            parameters.put("uri", uri);
        }

        final String charset = parameters.get("charset");
        if (charset == null) {
            String credentialsCharset = getCredentialsCharset(request);
            parameters.put("charset", credentialsCharset);
        }
        final NameValuePair digestHeader = createDigestHeader(credentials, request, parameters);
        return request.newBuilder().header(digestHeader.getName(), digestHeader.getValue()).build();
    }

    /**
     * Copy of implementation in `RequestLine.requestPath` as this sometimes produces field not found errors.
     *
     * @param url
     * @return
     */
    private String requestPath(final HttpUrl url) {
        String path = url.encodedPath();
        String query = url.encodedQuery();
        if (query != null) {
            return path + "?" + query;
        } else {
            return path;
        }
    }

    /**
     * Checks if the previous request had a digest authorization and its nonce
     * matches to the current server nonce. If that is the case, then we would
     * simply attempt the same authentication again and would fail again and again,
     * ...
     *
     * @param request the previous request
     * @param nonce   the current server nonce.
     * @param isStale when {@code true} then the server told us that the nonce was
     *                stale.
     * @return {@code true} in case the previous request already was authenticating
     * to the current server nonce.
     */
    private boolean havePreviousDigestAuthorizationAndShouldAbort(Request request, String nonce, boolean isStale) {
        final String headerKey;
        if (isProxy()) {
            headerKey = PROXY_AUTH_RESP;
        } else {
            headerKey = WWW_AUTH_RESP;
        }
        final String previousAuthorizationHeader = request.header(headerKey);

        if (previousAuthorizationHeader != null && previousAuthorizationHeader.startsWith("Digest")) {
            // only retry when the previous auth was stale
            return !isStale;
        }
        return false;
    }

    private void copyHeaderMap(Headers headers, Map<String, String> dest) {
        for (int i = 0; i < headers.size(); i++) {
            dest.put(headers.name(i), headers.value(i));
        }
    }

    /**
     * Creates digest-response header as defined in RFC2617.
     *
     * @param credentials User credentials
     * @return The digest-response as String.
     */
    // @edu.umd.cs.findbugs.annotations.SuppressFBWarnings("LSC_LITERAL_STRING_COMPARISON")
    private synchronized NameValuePair createDigestHeader(final Credentials credentials, final Request request,
                                                          final Map<String, String> parameters) throws AuthenticationException {
        final String uri = parameters.get("uri");
        final String realm = parameters.get("realm");
        final String nonce = parameters.get("nonce");
        final String opaque = parameters.get("opaque");
        final String method = parameters.get("methodname");
        String algorithm = parameters.get("algorithm");
        // If an algorithm is not specified, default to MD5.
        if (algorithm == null) {
            algorithm = "MD5";
        }

        final Set<String> qopset = new HashSet<>(8);
        int qop = QOP_UNKNOWN;
        final String qoplist = parameters.get("qop");
        if (qoplist != null) {
            final StringTokenizer tok = new StringTokenizer(qoplist, ",");
            while (tok.hasMoreTokens()) {
                final String variant = tok.nextToken().trim();
                qopset.add(variant.toLowerCase(Locale.US));
            }
            if (request.body() != null && qopset.contains("auth-int")) {
                qop = QOP_AUTH_INT;
            } else if (qopset.contains("auth")) {
                qop = QOP_AUTH;
            }
        } else {
            qop = QOP_MISSING;
        }

        if (qop == QOP_UNKNOWN) {
            throw new AuthenticationException("None of the qop methods is supported: " + qoplist);
        }

        String charset = parameters.get("charset");
        if (charset == null) {
            charset = "ISO-8859-1";
        }

        String digAlg = algorithm;
        if ("MD5-sess".equalsIgnoreCase(digAlg)) {
            digAlg = "MD5";
        }

        final MessageDigest digester;
        try {
            digester = createMessageDigest(digAlg);
        } catch (final UnsupportedDigestAlgorithmException ex) {
            throw new AuthenticationException("Unsuppported digest algorithm: " + digAlg, ex);
        }

        final String uname = credentials.getUserName();
        final String pwd = credentials.getPassword();

        if (nonce.equals(this.lastNonce)) {
            nounceCount++;
        } else {
            nounceCount = 1;
            cnonce = null;
            lastNonce = nonce;
        }
        final StringBuilder sb = new StringBuilder(256);
        final Formatter formatter = new Formatter(sb, Locale.US);
        formatter.format("%08x", nounceCount);
        formatter.close();
        final String nc = sb.toString();

        if (cnonce == null) {
            cnonce = createCnonce();
        }

        a1 = null;
        a2 = null;
        // 3.2.2.2: Calculating digest
        if ("MD5-sess".equalsIgnoreCase(algorithm)) {
            // H( unq(username-value) ":" unq(realm-value) ":" passwd )
            // ":" unq(nonce-value)
            // ":" unq(cnonce-value)

            // calculated one per session
            sb.setLength(0);
            sb.append(uname).append(':').append(realm).append(':').append(pwd);
            final String checksum = encode(digester.digest(getBytes(sb.toString(), charset)));
            sb.setLength(0);
            sb.append(checksum).append(':').append(nonce).append(':').append(cnonce);
            a1 = sb.toString();
        } else {
            // unq(username-value) ":" unq(realm-value) ":" passwd
            sb.setLength(0);
            sb.append(uname).append(':').append(realm).append(':').append(pwd);
            a1 = sb.toString();
        }

        final String hasha1 = encode(digester.digest(getBytes(a1, charset)));

        if (qop == QOP_AUTH) {
            // Method ":" digest-uri-value
            a2 = method + ':' + uri;
        } else if (qop == QOP_AUTH_INT) {
            // Method ":" digest-uri-value ":" H(entity-body)
            RequestBody entity = request.body();
            if (entity != null) {
                // If the entity is not repeatable, try falling back onto QOP_AUTH
                if (qopset.contains("auth")) {
                    qop = QOP_AUTH;
                    a2 = method + ':' + uri;
                } else {
                    throw new AuthenticationException("Qop auth-int cannot be used with " + "a non-repeatable entity");
                }
            } else {
                // code straight from
                // https://github.com/apache/httpclient/blob/4.3.x/httpclient/src/main/java/org/apache/http/impl/auth/DigestScheme.java#L363
                // not sure if this will actually work with an empty body.
                final HttpEntityDigester entityDigester = new HttpEntityDigester(digester);
                try {
                    entityDigester.close();
                } catch (final IOException ex) {
                    throw new AuthenticationException("I/O error reading entity content", ex);
                }
                a2 = method + ':' + uri + ':' + encode(entityDigester.getDigest());
            }
        } else {
            a2 = method + ':' + uri;
        }

        final String hasha2 = encode(digester.digest(getBytes(a2, charset)));

        // 3.2.2.1

        final String digestValue;
        if (qop == QOP_MISSING) {
            sb.setLength(0);
            sb.append(hasha1).append(':').append(nonce).append(':').append(hasha2);
            digestValue = sb.toString();
        } else {
            sb.setLength(0);
            sb.append(hasha1).append(':').append(nonce).append(':').append(nc).append(':').append(cnonce).append(':')
                    .append(qop == QOP_AUTH_INT ? "auth-int" : "auth").append(':').append(hasha2);
            digestValue = sb.toString();
        }

        final String digest = encode(digester.digest(getAsciiBytes(digestValue)));

        final StringBuilder buffer = new StringBuilder(128);
        final String headerKey;
        if (isProxy()) {
            headerKey = PROXY_AUTH_RESP;
        } else {
            headerKey = WWW_AUTH_RESP;
        }
        buffer.append("Digest ");

        final List<NameValuePair> params = new ArrayList<>(20);
        params.add(new BasicNameValuePair("username", uname));
        params.add(new BasicNameValuePair("realm", realm));
        params.add(new BasicNameValuePair("nonce", nonce));
        params.add(new BasicNameValuePair("uri", uri));
        params.add(new BasicNameValuePair("response", digest));

        if (qop != QOP_MISSING) {
            params.add(new BasicNameValuePair("qop", qop == QOP_AUTH_INT ? "auth-int" : "auth"));
            params.add(new BasicNameValuePair("nc", nc));
            params.add(new BasicNameValuePair("cnonce", cnonce));
        }
        // algorithm cannot be null here
        params.add(new BasicNameValuePair("algorithm", algorithm));
        if (opaque != null) {
            params.add(new BasicNameValuePair("opaque", opaque));
        }

        for (int i = 0; i < params.size(); i++) {
            final NameValuePair param = params.get(i);
            if (i > 0) {
                buffer.append(", ");
            }
            final String name = param.getName();
            final boolean noQuotes = ("nc".equals(name) || "qop".equals(name) || "algorithm".equals(name));
            BasicHeaderValueFormatter.DEFAULT.formatNameValuePair(buffer, param, !noQuotes);
        }
        return new BasicNameValuePair(headerKey, buffer.toString());
    }

    /**
     * Returns the charset used for the credentials.
     *
     * @return the credentials charset
     */
    public Charset getCredentialsCharset() {
        return credentialsCharset;
    }

    String getCredentialsCharset(final Request request) {
        String charset = request.header(CREDENTIAL_CHARSET);
        if (charset == null) {
            charset = getCredentialsCharset().name();
        }
        return charset;
    }

    private byte[] getBytes(final String s, final String charset) {
        try {
            return s.getBytes(charset);
        } catch (UnsupportedEncodingException e) {
            // try again with default encoding
            return s.getBytes();
        }
    }

    public byte[] getAsciiBytes(String data) {
        if (data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        } else {
            return data.getBytes(StandardCharsets.US_ASCII);
        }
    }

    public boolean isProxy() {
        return proxy;
    }

    public void setProxy(boolean proxy) {
        this.proxy = proxy;
    }


    private class AuthenticationException extends IOException {
        private static final long serialVersionUID = 1L;

        public AuthenticationException(String s) {
            super(s);
        }

        public AuthenticationException(String message, Exception ex) {
            super(message, ex);
        }
    }
}

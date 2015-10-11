
package com.burgstaller.okhttp.digest;

import android.util.Log;

import com.burgstaller.okhttp.digest.fromhttpclient.BasicHeaderValueFormatter;
import com.burgstaller.okhttp.digest.fromhttpclient.BasicHeaderValueParser;
import com.burgstaller.okhttp.digest.fromhttpclient.BasicNameValuePair;
import com.burgstaller.okhttp.digest.fromhttpclient.CharArrayBuffer;
import com.burgstaller.okhttp.digest.fromhttpclient.HeaderElement;
import com.burgstaller.okhttp.digest.fromhttpclient.HttpEntityDigester;
import com.burgstaller.okhttp.digest.fromhttpclient.NameValuePair;
import com.burgstaller.okhttp.digest.fromhttpclient.ParserCursor;
import com.burgstaller.okhttp.digest.fromhttpclient.UnsupportedDigestAlgorithmException;
import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.Headers;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Proxy;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Digest authenticator which is more or less the same code ripped out of Apache HTTP Client 4.3.1.
 */
public class DigestAuthenticator implements Authenticator {

    public static final String PROXY_AUTH = "Proxy-Authenticate";
    public static final String PROXY_AUTH_RESP = "Proxy-Authorization";
    public static final String WWW_AUTH = "WWW-Authenticate";
    public static final String WWW_AUTH_RESP = "Authorization";

    private static final String CREDENTIAL_CHARSET = "http.auth.credential-charset";
    private static final int QOP_UNKNOWN = -1;
    private static final int QOP_MISSING = 0;
    private static final int QOP_AUTH_INT = 1;
    private static final int QOP_AUTH = 2;
    private static final String TAG = "OkDigest";
    /**
     * Hexa values used when creating 32 character long digest in HTTP DigestScheme
     * in case of authentication.
     *
     * @see #encode(byte[])
     */
    private static final char[] HEXADECIMAL = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
            'e', 'f'
    };

    Map<String, String> parameters = new HashMap<>();
    private Charset credentialsCharset = Charset.forName("ASCII");
    private final Credentials credentials;
    private String lastNonce;
    private long nounceCount;
    private String cnonce;
    private String a1;
    private String a2;
    private boolean proxy;

    public DigestAuthenticator(Credentials credentials) {
        this.credentials = credentials;
    }

    private static MessageDigest createMessageDigest(
            final String digAlg) {
        try {
            return MessageDigest.getInstance(digAlg);
        } catch (final Exception e) {
            throw new IllegalArgumentException(
                    "Unsupported algorithm in HTTP Digest authentication: "
                            + digAlg);
        }
    }

    /**
     * Creates a random cnonce value based on the current time.
     *
     * @return The cnonce value as String.
     */
    public static String createCnonce() {
        final SecureRandom rnd = new SecureRandom();
        final byte[] tmp = new byte[8];
        rnd.nextBytes(tmp);
        return encode(tmp);
    }


    /**
     * Encodes the 128 bit (16 bytes) MD5 digest into a 32 characters long
     * <CODE>String</CODE> according to RFC 2617.
     *
     * @param binaryData array containing the digest
     * @return encoded MD5, or <CODE>null</CODE> if encoding failed
     */
    static String encode(final byte[] binaryData) {
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


    protected void parseChallenge(
            final String buffer, int pos, int len) {

        BasicHeaderValueParser parser = BasicHeaderValueParser.DEFAULT;
        ParserCursor cursor = new ParserCursor(pos, buffer.length());
        CharArrayBuffer buf = new CharArrayBuffer(len);
        buf.append(buffer);

        HeaderElement[] elements = parser.parseElements(buf, cursor);
        if (elements.length == 0) {
            throw new IllegalArgumentException("Authentication challenge is empty");
        }

        Map<String, String> params = getParameters();
        for (HeaderElement element : elements) {
            params.put(element.getName(), element.getValue());
        }
    }

    @Override
    public Request authenticate(Proxy proxy, Response response) throws IOException {

        String header = response.header("WWW-Authenticate");
        if (!header.startsWith("Digest")) {
            throw new IllegalArgumentException("unsupported auth scheme: " + header);
        }
        parseChallenge(header, 7, header.length() - 7);
        // first copy all request headers to our params array
        copyHeaderMap(response.headers(), parameters);
        final String realm = parameters.get("realm");
        if (realm == null) {
            Log.e(TAG, "missing realm in challenge");
            return null;
        }
        if (getParameter("nonce") == null) {
            throw new IllegalArgumentException("missing nonce in challenge");
        }
        // Add method name and request-URI to the parameter map
        final Request request = response.request();
        getParameters().put("methodname", request.method());
        getParameters().put("uri", request.uri().toASCIIString());
        final String charset = getParameter("charset");
        if (charset == null) {
            getParameters().put("charset", getCredentialsCharset(request));
        }
        final NameValuePair digestHeader = createDigestHeader(credentials, response.request());
        return response.request().newBuilder()
                .header(digestHeader.getName(), digestHeader.getValue())
                .build();
    }

    private void copyHeaderMap(Headers headers, Map<String, String> dest) {
        for (int i = 0; i < headers.size(); i++) {
            dest.put(headers.name(i), headers.value(i));
        }
    }

    private String getParameter(String key) {
        return parameters.get(key);
    }

    @Override
    public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
        return null;
    }

    /**
     * Creates digest-response header as defined in RFC2617.
     *
     * @param credentials User credentials
     * @return The digest-response as String.
     */
    private NameValuePair createDigestHeader(
            final Credentials credentials,
            final Request request) throws AuthenticationException {
        final String uri = getParameter("uri");
        final String realm = getParameter("realm");
        final String nonce = getParameter("nonce");
        final String opaque = getParameter("opaque");
        final String method = getParameter("methodname");
        String algorithm = getParameter("algorithm");
        // If an algorithm is not specified, default to MD5.
        if (algorithm == null) {
            algorithm = "MD5";
        }

        final Set<String> qopset = new HashSet<>(8);
        int qop = QOP_UNKNOWN;
        final String qoplist = getParameter("qop");
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

        String charset = getParameter("charset");
        if (charset == null) {
            charset = "ISO-8859-1";
        }

        String digAlg = algorithm;
        if (digAlg.equalsIgnoreCase("MD5-sess")) {
            digAlg = "MD5";
        }

        final MessageDigest digester;
        try {
            digester = createMessageDigest(digAlg);
        } catch (final UnsupportedDigestAlgorithmException ex) {
            throw new AuthenticationException("Unsuppported digest algorithm: " + digAlg);
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
        if (algorithm.equalsIgnoreCase("MD5-sess")) {
            // H( unq(username-value) ":" unq(realm-value) ":" passwd )
            //      ":" unq(nonce-value)
            //      ":" unq(cnonce-value)

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
            RequestBody entity = null;
            if (request.body() != null) {
                entity = request.body();
            }
            if (entity != null) {
                // If the entity is not repeatable, try falling back onto QOP_AUTH
                if (qopset.contains("auth")) {
                    qop = QOP_AUTH;
                    a2 = method + ':' + uri;
                } else {
                    throw new AuthenticationException("Qop auth-int cannot be used with " +
                            "a non-repeatable entity");
                }
            } else {
                final HttpEntityDigester entityDigester = new HttpEntityDigester(digester);
                try {
                    if (entity != null) {
                        entity.writeTo(entityDigester);
                    }
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
            sb.append(hasha1).append(':').append(nonce).append(':').append(nc).append(':')
                    .append(cnonce).append(':').append(qop == QOP_AUTH_INT ? "auth-int" : "auth")
                    .append(':').append(hasha2);
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

        final List<NameValuePair> params = new ArrayList<NameValuePair>(20);
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
            final boolean noQuotes = ("nc".equals(name) || "qop".equals(name)
                    || "algorithm".equals(name));
            BasicHeaderValueFormatter.DEFAULT.formatNameValuePair(buffer, param, !noQuotes);
        }
        return new BasicNameValuePair(headerKey, buffer.toString());
    }


    public Map<String, String> getParameters() {
        return parameters;
    }


    /**
     * @since 4.3
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
            final byte[] bytes = s.getBytes(charset);
            return bytes;
        } catch (UnsupportedEncodingException e) {
            // try again with default encoding
            return s.getBytes();
        }
    }
    public static byte[] getAsciiBytes(String data) {
        if(data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        } else {
            try {
                return data.getBytes("US-ASCII");
            } catch (UnsupportedEncodingException var2) {
                throw new Error("HttpClient requires ASCII support");
            }
        }
    }

    public boolean isProxy() {
        return proxy;
    }

    public void setProxy(boolean proxy) {
        this.proxy = proxy;
    }

    private class AuthenticationException extends IllegalStateException {
        public AuthenticationException(String s) {
            super(s);
        }

        public AuthenticationException(String message, Exception ex) {
            super(message, ex);
        }
    }
}

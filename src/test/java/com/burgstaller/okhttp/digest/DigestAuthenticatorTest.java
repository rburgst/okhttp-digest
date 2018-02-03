package com.burgstaller.okhttp.digest;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.net.SocketFactory;

import okhttp3.Address;
import okhttp3.Authenticator;
import okhttp3.Connection;
import okhttp3.ConnectionSpec;
import okhttp3.Dns;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.text.MatchesPattern.matchesPattern;
import static org.junit.Assert.assertThat;
import static org.mockito.BDDMockito.given;

public class DigestAuthenticatorTest {

    private Route mockRoute;
    private DigestAuthenticator authenticator;

    @Before
    public void beforeMethod() {
        Connection mockConnection = mock(Connection.class);
        Dns mockDns = mock(Dns.class);
        SocketFactory socketFactory = mock(SocketFactory.class);
        Authenticator proxyAuthenticator = mock(Authenticator.class);
        ProxySelector proxySelector = mock(ProxySelector.class);
        Proxy proxy = mock(Proxy.class);

        // setup some dummy data so that we dont get NPEs
        Address address = new Address("localhost", 8080, mockDns, socketFactory, null, null,
                null, proxyAuthenticator, null, Collections.singletonList(Protocol.HTTP_1_1),
                Collections.singletonList(ConnectionSpec.MODERN_TLS), proxySelector);
        InetSocketAddress inetSocketAddress = new InetSocketAddress("localhost", 8080);
        mockRoute = new Route(address, proxy, inetSocketAddress);
        given(mockConnection.route()).willReturn(mockRoute);

        authenticator = new DigestAuthenticator(new Credentials("user1", "user1"));
    }

    @Test
    public void testWWWAuthenticate_shouldWork() throws Exception {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .build();
        Request authenticated = authenticator.authenticate(mockRoute, response);

        assertThat(authenticated.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", " +
                        "nonce=\"BBBBBB\", " +
                        "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testWWWAuthenticate__withMultipleRequestsToSameSite__shouldCacheAuthParams() throws Exception {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .build();
        Request authenticated = authenticator.authenticate(mockRoute, response);

        assertThat(authenticated.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", " +
                        "nonce=\"BBBBBB\", " +
                        "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));

        // when
        Request secondRequest = new Request.Builder()
                .url("http://www.google.com/account")
                .get()
                .build();
        Request secondAuthenticatedRequest = authenticator.authenticateWithState(mockRoute, secondRequest);
        assertThat(secondAuthenticatedRequest.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", " +
                        "nonce=\"BBBBBB\", " +
                        "uri=\"/account\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testProxyAuthenticate__shouldWork() throws Exception {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(407)
                .message("Proxy Authentication Required")
                .header("Proxy-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .build();
        Request authenticated = authenticator.authenticate(mockRoute, response);

        assertThat(authenticated.header("Proxy-Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", " +
                  "nonce=\"BBBBBB\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWWWAuthenticate__withInvalidWWWAuthHeader__shouldThrowException() throws Exception {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate",
                        "Digest realm=\"myrealm\", algorithm=MD5, qop=\"auth\"")
                .build();
        try {
            authenticator.authenticate(null, response);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    public void testWWWAuthenticate__withUriPathAndParameters() throws Exception {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com/path/to/resource?parameter=value&parameter2=value2")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .build();
        Request authenticated = authenticator.authenticate(mockRoute, response);

        String authHeader = authenticated.header("Authorization");
        assertThat(authHeader,
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", " +
                  "nonce=\"BBBBBB\", " +
                  "uri=\"/path/to/resource\\?parameter=value&parameter2=value2\", " +
                  "response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testWWWAuthenticate__withUriPathAndParametersAndNullRoute() throws Exception {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com/path/to/resource?parameter=value&parameter2=value2")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .build();
        Request authenticated = authenticator.authenticate(null, response);

        String authHeader = authenticated.header("Authorization");
        assertThat(authHeader,
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", " +
                  "nonce=\"BBBBBB\", " +
                  "uri=\"/path/to/resource\\?parameter=value&parameter2=value2\", " +
                  "response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testWWWAuthenticate_withMultipleAuthResponseHeaders_shouldWork() throws IOException {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .addHeader("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .addHeader("WWW-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();
        Request authenticated = authenticator.authenticate(mockRoute, response);

        assertThat(authenticated.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", " +
                  "nonce=\"BBBBBB\", uri=\"/\", " +
                  "response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testWWWAuthenticate_withWrongPassword_shouldNotRepeat() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Authorization", "Digest username=\"user1\", realm=\"myrealm\", " +
                  "nonce=\"BBBBBB\", uri=\"/\", " +
                  "response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .addHeader("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .addHeader("WWW-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request result = authenticator.authenticate(mockRoute, response);

        // then
        assertThat(result, is(nullValue()));
    }

    @Test
    public void testWWWAuthenticate_withDifferentNonce_shouldNotRetry() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Authorization", "Digest username=\"user1\", realm=\"myrealm\", nonce=\"AAAAAAA\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .addHeader("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .addHeader("WWW-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request authenticated = authenticator.authenticate(null, response);

        // then
        assertThat(authenticated, is(nullValue()));
    }

    @Test
    public void testWWWAuthenticate_withDifferentNonceAndStale_shouldRetry() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Authorization", "Digest username=\"user1\", realm=\"myrealm\", nonce=\"AAAAAAA\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .addHeader("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\", stale=true")
                .addHeader("WWW-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request authenticated = authenticator.authenticate(mockRoute, response);

        // then
        assertThat(authenticated.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", nonce=\"BBBBBB\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testWWWAuthenticate_withDifferentNonceAndStaleAndQuotes_shouldRetry() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Authorization", "Digest username=\"user1\", realm=\"myrealm\", nonce=\"AAAAAAA\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .addHeader("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\", stale=\"true\"")
                .addHeader("WWW-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request authenticated = authenticator.authenticate(mockRoute, response);

        // then
        assertThat(authenticated.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", nonce=\"BBBBBB\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }


    @Test
    public void testProxyAuthenticate_withDifferentNonce_shouldNotRetry() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Proxy-Authorization", "Digest username=\"user1\", realm=\"myrealm\", nonce=\"AAAAAAA\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(407)
                .message("Proxy Authentication Required")
                .addHeader("Proxy-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"")
                .addHeader("Proxy-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request authenticated = authenticator.authenticate(null, response);

        // then
        assertThat(authenticated, is(nullValue()));
    }

    @Test
    public void testProxyAuthenticate_withDifferentNonceAndStale_shouldRetry() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Proxy-Authorization", "Digest username=\"user1\", realm=\"myrealm\", nonce=\"AAAAAAA\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(407)
                .message("Proxy Authentication Required")
                .addHeader("Proxy-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\", stale=true")
                .addHeader("Proxy-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request authenticated = authenticator.authenticate(mockRoute, response);

        // then
        assertThat(authenticated.header("Proxy-Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", nonce=\"BBBBBB\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testProxyAuthenticate_withDifferentNonceAndStaleAndQuotes_shouldRetry() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Proxy-Authorization", "Digest username=\"user1\", realm=\"myrealm\", nonce=\"AAAAAAA\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(407)
                .message("Proxy Authentication Required")
                .addHeader("Proxy-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\", stale=\"true\"")
                .addHeader("Proxy-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request authenticated = authenticator.authenticate(mockRoute, response);

        // then
        assertThat(authenticated.header("Proxy-Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", nonce=\"BBBBBB\", " +
                  "uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    /**
     * Tests a case where the digest authenticator is used in tandem with another authenticator and
     * DispatchingAuthenticator will call authenticateWithState on all registered authenticators
     * even when they dont have an initial state.
     */
    @Test
    public void testWWWAuthenticateWithState__whenNoInitialStateWasGiven__shouldNotThrowException() throws Exception {
        Request secondRequest = new Request.Builder()
                .url("http://www.google.com/account")
                .get()
                .build();
        CachingAuthenticator localAuthenticator = new DigestAuthenticator(new Credentials("user1", "user1"));

        Request authenticatedRequest = localAuthenticator.authenticateWithState(mockRoute, secondRequest);
        assertNull(authenticatedRequest);
    }


    @Test
    public void testMultithreadedWWWAuthenticate() throws Exception {
        final DigestAuthenticatorTest test = this;
        final ConcurrentHashMap<String,Exception> exceptions = new ConcurrentHashMap<>();
        ExecutorService executor = new ThreadPoolExecutor(20, 20, 1, TimeUnit.MINUTES, new LinkedBlockingQueue());
        for ( final Method method : this.getClass().getDeclaredMethods() ) {
            if ( method.getName().startsWith("testWWWAuthenticate") &&
                 ! method.getName().endsWith("shouldThrowException") ) {
                executor.execute(new Runnable() {
                    public void run() {
                        try {
                            System.out.println("invoking method=" + method.getName());
                            method.invoke(test);
                        } catch(Exception e) {
                            exceptions.put(method.getName(), e);
                        }
                    }
                });
            }
        }
        executor.shutdown();
        try {
            executor.awaitTermination(2, TimeUnit.MINUTES);
        } catch(InterruptedException e) {
            throw new IllegalStateException("Timeout trying to run testMultithreadedAuthenticate");
        }
        if ( exceptions.size() > 0 ) {
            for ( String methodName : exceptions.keySet() ) {
                System.err.println("Test " + methodName + " failed under testMultithreadedAuthenticate:");
                exceptions.get(methodName).printStackTrace();
            }
            throw exceptions.elements().nextElement();
        }
    }

    @Test
    public void testMultithreadedProxyAuthenticate() throws Exception {
        final DigestAuthenticatorTest test = this;
        final ConcurrentHashMap<String,Exception> exceptions = new ConcurrentHashMap<>();
        ExecutorService executor = new ThreadPoolExecutor(20, 20, 1, TimeUnit.MINUTES, new LinkedBlockingQueue());
        for ( final Method method : this.getClass().getDeclaredMethods() ) {
            if ( method.getName().startsWith("testProxyAuthenticate") &&
                 ! method.getName().endsWith("shouldThrowException") ) {
                executor.execute(new Runnable() {
                    public void run() {
                        try {
                            System.out.println("invoking method=" + method.getName());
                            method.invoke(test);
                        } catch(Exception e) {
                            exceptions.put(method.getName(), e);
                        }
                    }
                });
            }
        }
        executor.shutdown();
        try {
            executor.awaitTermination(2, TimeUnit.MINUTES);
        } catch(InterruptedException e) {
            throw new IllegalStateException("Timeout trying to run testMultithreadedAuthenticate");
        }
        if ( exceptions.size() > 0 ) {
            for ( String methodName : exceptions.keySet() ) {
                System.err.println("Test " + methodName + " failed under testMultithreadedAuthenticate:");
                exceptions.get(methodName).printStackTrace();
            }
            throw exceptions.elements().nextElement();
        }
    }
}


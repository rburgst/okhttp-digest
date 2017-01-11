package com.burgstaller.okhttp;

import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;

import org.hamcrest.text.MatchesPattern;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.SocketFactory;

import okhttp3.Address;
import okhttp3.Authenticator;
import okhttp3.Connection;
import okhttp3.ConnectionSpec;
import okhttp3.Dns;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.Route;

import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.junit.Assert.*;
import static org.mockito.BDDMockito.given;

/**
 * Unit test for authenticator caching.
 *
 * @author Alexey Vasilyev
 */
public class AuthenticationCacheInterceptorTest {

    @Mock
    private Connection mockConnection;
    private Route mockRoute;
    @Mock
    private Dns mockDns;
    @Mock
    private SocketFactory socketFactory;
    @Mock
    private Authenticator proxyAuthenticator;
    @Mock
    private ProxySelector proxySelector;
    @Mock
    Proxy proxy;

    @Before
    public void beforeMethod() {
        MockitoAnnotations.initMocks(this);

        // setup some dummy data so that we dont get NPEs
        Address address = new Address("localhost", 8080, mockDns, socketFactory, null, null,
                null, proxyAuthenticator, null, Collections.singletonList(Protocol.HTTP_1_1),
                Collections.singletonList(ConnectionSpec.MODERN_TLS), proxySelector);
        InetSocketAddress inetSocketAddress = new InetSocketAddress("localhost", 8080);
        mockRoute = new Route(address, proxy, inetSocketAddress);
        given(mockConnection.route()).willReturn(mockRoute);
    }

    @Test
    public void testCaching_withExpiredAuthentication() throws Exception {
        Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

        final String dummyUrl = "https://myhost.com/path";

        // Fill in authCache.
        // https://myhost.com => basic auth user1:user1
        givenCachedAuthenticationFor(dummyUrl, authCache);
        assertEquals(1, authCache.size());

        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);

        // Check that unauthorized response (e.g. credentials changed or expired)
        // removes cached authenticator
        whenServerReturns401(dummyUrl, interceptor);

        thenAuthCacheShouldBeEmpty(authCache);
    }

    private void whenServerReturns401(final String dummyUrl, Interceptor interceptor) throws IOException {
        interceptor.intercept(new Interceptor.Chain() {
            @Override
            public Request request() {
                return new Request.Builder()
                        .url(dummyUrl)
                        .get()
                        .build();
            }

            @Override
            public Response proceed(Request request) throws IOException {
                Response response = givenUnauthorizedServerResponse(request);
                return response;
            }

            @Override
            public Connection connection() {
                return mockConnection;
            }
        });
    }

    private void thenAuthCacheShouldBeEmpty(Map<String, CachingAuthenticator> authCache) {
        // No cached authenticator anymore
        assertEquals(0, authCache.size());
    }

    @Test
    public void testCaching_withDifferentPorts() throws Exception {
        Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

        // Fill in authCache.
        // https://myhost.com => basic auth user1:user1
        givenCachedAuthenticationFor("https://myhost.com", authCache);
        assertEquals(1, authCache.size());

        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);

        // Check that authenticator exists for https://myhost.com:443
        final String authorization = whenInterceptAuthenticationForUrl(interceptor, "https://myhost.com:443");
        thenAuthorizationHeaderShouldBePresent(authorization);

        // Check that authenticator does not exist for http://myhost.com:8080
        final String authorization2 = whenInterceptAuthenticationForUrl(interceptor, "http://myhost.com:8080");
        thenNoAuthorizationHeaderShouldBePresent(authorization2);
    }

    private void thenNoAuthorizationHeaderShouldBePresent(String authorization2) {
        assertNull(authorization2);
    }

    private void thenAuthorizationHeaderShouldBePresent(String authorization) {
        assertThat(authorization, MatchesPattern.matchesPattern("Basic dXNlcjE6dXNlcjE="));
    }

    private String whenInterceptAuthenticationForUrl(Interceptor interceptor, final String url) throws IOException {
        // we need a result holder for passing into the anonymous class
        final AtomicReference<String> authResultHeader = new AtomicReference<>();
        interceptor.intercept(new Interceptor.Chain() {
            @Override
            public Request request() {
                return new Request.Builder()
                        .url(url)
                        .get()
                        .build();
            }

            @Override
            public Response proceed(Request request) throws IOException {
                final String authorization = request.header("Authorization");
                authResultHeader.set(authorization);
                return null;
            }

            @Override
            public Connection connection() {
                return mockConnection;
            }
        });
        return authResultHeader.get();
    }

    private void givenCachedAuthenticationFor(String url, Map<String, CachingAuthenticator> authCache) throws IOException {
        Authenticator decorator = new CachingAuthenticatorDecorator(
                new BasicAuthenticator(new Credentials("user1", "user1")),
                authCache);
        Request dummyRequest = new Request.Builder()
                .url(url)
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(HTTP_UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                .build();
        decorator.authenticate(null, response);
    }

    private Response givenUnauthorizedServerResponse(Request request) {
        return new Response.Builder()
                .body(ResponseBody.create(MediaType.parse("text/plain"), "Unauthorized"))
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(HTTP_UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                .build();
    }
}

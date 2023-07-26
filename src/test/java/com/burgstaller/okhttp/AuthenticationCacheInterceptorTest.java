package com.burgstaller.okhttp;

import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;
import okhttp3.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.net.SocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
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

    @BeforeEach
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
        assertThat(authCache).hasSize(1);

        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);

        // Check that unauthorized response (e.g. credentials changed or expired)
        // removes cached authenticator
        whenServerReturns401(dummyUrl, interceptor);

        thenAuthCacheShouldBeEmpty(authCache);
    }

    private void whenServerReturns401(final String dummyUrl, Interceptor interceptor) throws IOException {
        Request request = new Request.Builder()
                .url(dummyUrl)
                .get()
                .build();
        interceptor.intercept(new ChainAdapter(request, mockConnection) {

            @Override
            public Response proceed(Request request) {
                Response response = givenUnauthorizedServerResponse(request);
                return response;
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

    @Test
    public void testCaching__whenNoConnectionExists__shouldNotBombOut() throws IOException {
        Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);

        String auth = whenInterceptAuthenticationForUrlWithNoConnection(interceptor, "https://myhost.com:443");
        assertNull(auth);
    }

    @Test
    public void testCaching__whenNoConnectionExistsButCachedInfo__shouldNotBombOut() throws IOException {
        Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
        givenCachedAuthenticationFor("https://myhost.com:443", authCache);
        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);

        // when
        String auth = whenInterceptAuthenticationForUrlWithNoConnection(interceptor, "https://myhost.com:443");
        thenAuthorizationHeaderShouldBePresent(auth);
    }

    private void thenNoAuthorizationHeaderShouldBePresent(String authorization2) {
        assertNull(authorization2);
    }

    private void thenAuthorizationHeaderShouldBePresent(String authorization) {
        assertThat(authorization).matches("Basic dXNlcjE6dXNlcjE=");
    }

    private String whenInterceptAuthenticationForUrl(Interceptor interceptor, final String url) throws IOException {
        // we need a result holder for passing into the anonymous class
        final AtomicReference<String> authResultHeader = new AtomicReference<>();
        final Request request = new Request.Builder()
                .url(url)
                .get()
                .build();
        interceptor.intercept(new ChainAdapter(request, mockConnection) {
            @Override
            public Response proceed(Request request) {
                final String authorization = request.header("Authorization");
                authResultHeader.set(authorization);
                return null;
            }
        });
        return authResultHeader.get();
    }

    private String whenInterceptAuthenticationForUrlWithNoConnection(Interceptor interceptor, final String url) throws IOException {
        // we need a result holder for passing into the anonymous class
        final AtomicReference<String> authResultHeader = new AtomicReference<>();
        final Request request = new Request.Builder()
                .url(url)
                .get()
                .build();

        interceptor.intercept(new ChainAdapter(request, mockConnection) {
            @Override
            public Response proceed(Request request) {
                final String authorization = request.header("Authorization");
                authResultHeader.set(authorization);
                return null;
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
                .message("Unauthorized")
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
                .message("Unauthorized")
                .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                .build();
    }
}

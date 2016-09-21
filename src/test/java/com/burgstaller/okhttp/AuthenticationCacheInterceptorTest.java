package com.burgstaller.okhttp;

import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;

import org.hamcrest.text.MatchesPattern;
import org.junit.Test;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import okhttp3.Authenticator;
import okhttp3.Connection;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import static org.junit.Assert.*;

/**
 * Unit test for authenticator caching.
 *
 * @author Alexey Vasilyev
 */
public class AuthenticationCacheInterceptorTest {

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
                return new Response.Builder()
                        .body(ResponseBody.create(MediaType.parse("text/plain"), "Unauthorized"))
                        .request(request)
                        .protocol(Protocol.HTTP_1_1)
                        .code(401)
                        .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                        .build();
            }
            @Override
            public Connection connection() {
                return null;
            }
        });
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
                .code(401)
                .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                .build();
        decorator.authenticate(null, response);
    }
}

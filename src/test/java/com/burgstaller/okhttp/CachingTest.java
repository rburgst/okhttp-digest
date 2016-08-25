package com.burgstaller.okhttp;

import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;

import junit.framework.Assert;

import org.hamcrest.text.MatchesPattern;
import org.junit.Test;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import okhttp3.Authenticator;
import okhttp3.Connection;
import okhttp3.Interceptor;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;

import static org.junit.Assert.*;

/**
 * Unit test for authenticator caching.
 *
 * @author Alexey Vasilyev
 */
public class CachingTest {

    @Test
    public void testCaching_withDifferentPorts() throws Exception {
        Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

        // Fill in authCache.
        // https://myhost.com => basic auth user1:user1
        Authenticator decorator = new CachingAuthenticatorDecorator(
                new BasicAuthenticator(new Credentials("user1", "user1")),
                authCache);
        Request dummyRequest = new Request.Builder()
                .url("https://myhost.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                .build();
        decorator.authenticate(null, response);
        Assert.assertTrue(authCache.size() == 1);


        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);

        // Check that authenticator exists for https://myhost.com:443
        interceptor.intercept(new Interceptor.Chain() {
            @Override
            public Request request() {
                return new Request.Builder()
                        .url("https://myhost.com:443")
                        .get()
                        .build();
            }
            @Override
            public Response proceed(Request request) throws IOException {
                assertThat(request.header("Authorization"), MatchesPattern.matchesPattern("Basic dXNlcjE6dXNlcjE="));
                return null;
            }
            @Override
            public Connection connection() {
                return null;
            }
        });


        // Check that authenticator does not exist for http://myhost.com:8080
        interceptor.intercept(new Interceptor.Chain() {
            @Override
            public Request request() {
                return new Request.Builder()
                        .url("http://myhost.com:8080")
                        .get()
                        .build();
            }
            @Override
            public Response proceed(Request request) throws IOException {
                assertNull(request.header("Authorization"));
                return null;
            }
            @Override
            public Connection connection() {
                return null;
            }
        });
    }

}

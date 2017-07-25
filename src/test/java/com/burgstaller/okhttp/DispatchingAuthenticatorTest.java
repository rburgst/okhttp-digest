package com.burgstaller.okhttp;

import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;
import com.burgstaller.okhttp.digest.DigestAuthenticator;

import org.junit.Assert;
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
import static org.mockito.BDDMockito.given;

public class DispatchingAuthenticatorTest {

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
    public void testCaching_withDigestAuthenticatorPreferredOrder() throws Exception {
        final Credentials credentials = new Credentials("user", "pwd");
        final BasicAuthenticator basicAuthenticator = new BasicAuthenticator(credentials);
        final DigestAuthenticator digestAuthenticator = new DigestAuthenticator(credentials);
        DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder()
                .with("digest", digestAuthenticator)
                .with("basic", basicAuthenticator)
                .build();

        Request request = authenticator.authenticate(mockRoute, createUnauthorizedServerResponse());
        Assert.assertNotNull(request);

        request = authenticator.authenticateWithState(mockRoute, createDummyRequest());
        Assert.assertNotNull(request);
    }

    @Test
    public void testCaching_withBasicAuthenticatorPreferredOrder() throws Exception {
        final Credentials credentials = new Credentials("user", "pwd");
        final BasicAuthenticator basicAuthenticator = new BasicAuthenticator(credentials);
        final DigestAuthenticator digestAuthenticator = new DigestAuthenticator(credentials);
        DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder()
                .with("digest", digestAuthenticator)
                .with("basic", basicAuthenticator)
                .build();

        Request request = authenticator.authenticate(mockRoute, createUnauthorizedServerResponse());
        Assert.assertNotNull(request);

        request = authenticator.authenticateWithState(mockRoute, createDummyRequest());
        Assert.assertNotNull(request);
    }

    private Response createUnauthorizedServerResponse() throws IOException {
        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);
        return interceptor.intercept(new Interceptor.Chain() {
            @Override
            public Request request() {
                return createDummyRequest();
            }

            @Override
            public Response proceed(Request request) throws IOException {
                return new Response.Builder()
                        .body(ResponseBody.create(MediaType.parse("text/plain"), "Unauthorized"))
                        .request(request)
                        .protocol(Protocol.HTTP_1_1)
                        .code(HTTP_UNAUTHORIZED)
                        .message("Unauthorized")
                        .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                        .build();
            }

            @Override
            public Connection connection() {
                return mockConnection;
            }
        });
    }

    private Request createDummyRequest() {
        final String dummyUrl = "https://myhost.com/path";
        return new Request.Builder()
                .url(dummyUrl)
                .get()
                .build();
    }
}

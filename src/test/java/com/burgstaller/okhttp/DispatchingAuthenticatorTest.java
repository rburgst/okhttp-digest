package com.burgstaller.okhttp;

import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;
import com.burgstaller.okhttp.digest.DigestAuthenticator;
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
import org.hamcrest.CoreMatchers;
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

import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

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

    @BeforeEach
    public void beforeMethod() {
        MockitoAnnotations.initMocks(this);

        // setup some dummy data so that we dont get NPEs
        Address address = new Address("localhost", 8080, mockDns, socketFactory, null, null, null, proxyAuthenticator,
                null, Collections.singletonList(Protocol.HTTP_1_1),
                Collections.singletonList(ConnectionSpec.MODERN_TLS), proxySelector);
        InetSocketAddress inetSocketAddress = new InetSocketAddress("localhost", 8080);
        mockRoute = new Route(address, proxy, inetSocketAddress);
        given(mockConnection.route()).willReturn(mockRoute);
    }

    /**
     * Makes sure that in the case of cached authenticators the authenticators are
     * called in the order in which they were registered.
     *
     * @throws Exception
     */
    @Test
    public void testAuthenticateWithState__shouldCallAuthenticatorsInExpectedOrder() throws Exception {
        // given
        CachingAuthenticator auth1 = mock(CachingAuthenticator.class);
        CachingAuthenticator auth2 = mock(CachingAuthenticator.class);

        DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder().with("digest", auth1)
                .with("basic", auth2).build();
        Request request = createDummyRequest();
        // make sure that the 2nd authenticator will not be called
        given(auth2.authenticateWithState(eq(mockRoute), eq(request))).willThrow(IllegalStateException.class);
        given(auth1.authenticateWithState(eq(mockRoute), eq(request))).willReturn(request);

        // when
        Request result = authenticator.authenticateWithState(mockRoute, request);

        // then
        assertEquals(request, result);
    }

    /**
     * Makes sure that we dont throw an exception for unknown schemes.
     *
     * @throws Exception
     */
    @Test
    public void testAuthenticate__whenUnknownScheme__shouldNotThrowException() throws Exception {
        // given
        CachingAuthenticator auth1 = mock(CachingAuthenticator.class);

        // only digest, no basic auth
        DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder().with("digest", auth1).build();

        // when
        Request request = authenticator.authenticate(mockRoute, createUnauthorizedServerResponse());

        // then
        assertNull(request);
    }

    @Test
    public void testCaching_withDigestAuthenticatorPreferredOrder() throws Exception {
        final Credentials credentials = new Credentials("user", "pwd");
        final BasicAuthenticator basicAuthenticator = new BasicAuthenticator(credentials);
        final DigestAuthenticator digestAuthenticator = new DigestAuthenticator(credentials);
        DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder()
                .with("digest", digestAuthenticator).with("basic", basicAuthenticator).build();

        Request request = authenticator.authenticate(mockRoute, createUnauthorizedServerResponse());
        assertNotNull(request);
        String authorizationHeader = request.header("Authorization");
        assertThat(authorizationHeader, CoreMatchers.startsWith("Basic"));

        request = authenticator.authenticateWithState(mockRoute, createDummyRequest());
        assertNotNull(request);
    }

    @Test
    public void testCaching_withBasicAuthenticatorPreferredOrder() throws Exception {
        final Credentials credentials = new Credentials("user", "pwd");
        final BasicAuthenticator basicAuthenticator = new BasicAuthenticator(credentials);
        final DigestAuthenticator digestAuthenticator = new DigestAuthenticator(credentials);
        DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder()
                .with("basic", basicAuthenticator).with("digest", digestAuthenticator).build();

        Request request = authenticator.authenticate(mockRoute, createUnauthorizedServerResponse());
        assertNotNull(request);

        request = authenticator.authenticateWithState(mockRoute, createDummyRequest());
        assertNotNull(request);
    }

    private Response createUnauthorizedServerResponse() throws IOException {
        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
        Interceptor interceptor = new AuthenticationCacheInterceptor(authCache);
        return interceptor.intercept(new ChainAdapter(createDummyRequest(), mockConnection) {
            @Override
            public Response proceed(Request request) throws IOException {
                return new Response.Builder().body(ResponseBody.create(MediaType.parse("text/plain"), "Unauthorized"))
                        .request(request).protocol(Protocol.HTTP_1_1).code(HTTP_UNAUTHORIZED).message("Unauthorized")
                        .header("WWW-Authenticate", "Basic realm=\"myrealm\"").build();
            }

        });
    }

    private Request createDummyRequest() {
        final String dummyUrl = "https://myhost.com/path";
        return new Request.Builder().url(dummyUrl).get().build();
    }

}

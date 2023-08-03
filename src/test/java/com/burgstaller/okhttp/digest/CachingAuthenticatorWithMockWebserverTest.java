package com.burgstaller.okhttp.digest;

import com.burgstaller.okhttp.AuthenticationCacheInterceptor;
import com.burgstaller.okhttp.CachingAuthenticatorDecorator;
import com.burgstaller.okhttp.DispatchingAuthenticator;
import com.burgstaller.okhttp.basic.StdOutLogger;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import okhttp3.logging.HttpLoggingInterceptor;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit test for basic authenticator.
 *
 * @author Rainer Burgstaller
 */
public class CachingAuthenticatorWithMockWebserverTest {

    @Rule
    public MockWebServer mockServer = new MockWebServer();

    private OkHttpClient client;
    private MockResponse unauthorizedResponse;
    private MockResponse successResponse;
    private Credentials credentials;
    private Map<String, CachingAuthenticator> authCache;
    private DigestAuthenticator digestAuthenticator;
    private CachingAuthenticatorDecorator sut;
    private AuthenticationCacheInterceptor authenticationCacheInterceptor;
    private DigestAuthenticator digestSpy;
    private String expectedDigestClientAuthHeaderRegexp;
    private String expectedDigestClientAuthHeaderUser2Regexp;

    @BeforeEach
    public void setUp() {
        authCache = new ConcurrentHashMap<>();
        credentials = new Credentials("user1", "user1");
        digestAuthenticator = new DigestAuthenticator(credentials);

        digestSpy = spy(digestAuthenticator);
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

        HttpLoggingInterceptor logger = new HttpLoggingInterceptor(new StdOutLogger());
        logger.setLevel(HttpLoggingInterceptor.Level.HEADERS);
        authenticationCacheInterceptor = new AuthenticationCacheInterceptor(authCache);

        DispatchingAuthenticator dispatchingAuthenticator = new DispatchingAuthenticator.Builder()
                .with("digest", digestSpy)
                .build();
        sut = new CachingAuthenticatorDecorator(dispatchingAuthenticator, authCache);
        client = builder
                .authenticator(sut)
                .addInterceptor(authenticationCacheInterceptor)
                .addNetworkInterceptor(logger)
                .build();

        unauthorizedResponse = new MockResponse()
                .setResponseCode(401)
                .addHeader("WWW-Authenticate", "Digest realm=\"myrealm\", nonce=\"BBBBBB\", algorithm=MD5, qop=\"auth\"");
        successResponse = new MockResponse().setBody("OK");

        expectedDigestClientAuthHeaderRegexp = "Digest username=\"user1\", realm=\"myrealm\", " +
                "nonce=\"BBBBBB\", uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5";
        expectedDigestClientAuthHeaderUser2Regexp = "Digest username=\"user2\", realm=\"myrealm\", " +
                "nonce=\"BBBBBB\", uri=\"/\", response=\"[0-9a-f]+\", qop=auth, nc=000000\\d\\d, cnonce=\"[0-9a-f]+\", algorithm=MD5";
    }

    @Test
    public void testAuthenticate() throws Exception {
        Request dummyRequest = new Request.Builder()
                .url(mockServer.url("/"))
                .get()
                .build();

        mockServer.enqueue(unauthorizedResponse);
        mockServer.enqueue(successResponse);

        Response response = client.newCall(dummyRequest).execute();
        RecordedRequest firstRequest = mockServer.takeRequest();
        RecordedRequest secondRequest = mockServer.takeRequest();

        assertThat(firstRequest.getHeader("Authorization")).isNull();
        assertThat(secondRequest.getHeader("Authorization")).matches(expectedDigestClientAuthHeaderRegexp);
        assertThat(response.body().string()).isEqualTo("OK");
    }

    @Test
    public void testAuthenticate__withWrongPassword__shouldNotRepeat() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url(mockServer.url("/"))
                .get()
                .build();
        mockServer.enqueue(unauthorizedResponse);
        mockServer.enqueue(unauthorizedResponse);

        // when
        Response response = client.newCall(dummyRequest).execute();

        // then
        verify(digestSpy, times(2)).authenticate(any(Route.class), any(Response.class));
        assertThat(response.code()).isEqualTo(401);
    }

    @Test
    public void testAuthenticate__whenChangeCredentials__shouldRepeat() throws IOException, InterruptedException {
        // given
        Request dummyRequest = new Request.Builder()
                .url(mockServer.url("/"))
                .get()
                .build();
        mockServer.enqueue(unauthorizedResponse);
        mockServer.enqueue(unauthorizedResponse);

        Response response = client.newCall(dummyRequest).execute();
        assertThat(response.code()).isEqualTo(401);

        // when
        // now we inject new credentials
        credentials.setUserName("user2");
        mockServer.enqueue(successResponse);

        // when we now create a brand new call to the server
        Response response2 = client.newCall(dummyRequest).execute();

        // then
        // we should authenticate successfully
        assertThat(response2.isSuccessful()).isTrue();
        assertThat(response2.body().string()).isEqualTo("OK");

        // in total there are 3 requests sent
        RecordedRequest req1 = mockServer.takeRequest();
        RecordedRequest req2 = mockServer.takeRequest();
        RecordedRequest req3 = mockServer.takeRequest();
        assertThat(req1.getHeader("Authorization")).isNull();
        assertThat(req2.getHeader("Authorization")).matches(expectedDigestClientAuthHeaderRegexp);
        assertThat(req3.getHeader("Authorization")).matches(expectedDigestClientAuthHeaderUser2Regexp);
    }

}
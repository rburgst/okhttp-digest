package com.burgstaller.okhttp.basic;

import com.burgstaller.okhttp.AuthenticationCacheInterceptor;
import com.burgstaller.okhttp.CachingAuthenticatorDecorator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;
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
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Unit test for basic authenticator.
 *
 * @author Rainer Burgstaller
 */
public class BasicAuthenticatorWithMockWebserverTest {

    @Rule
    public MockWebServer mockServer = new MockWebServer();

    private BasicAuthenticator sut;
    private BasicAuthenticator spy;
    private OkHttpClient client;
    private MockResponse unauthorizedResponse;
    private MockResponse successResponse;
    private Credentials credentials;

    @BeforeEach
    public void setUp() throws Exception {
        credentials = new Credentials("user1", "user1");
        sut = new BasicAuthenticator(credentials);
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

        HttpLoggingInterceptor logger = new HttpLoggingInterceptor(new StdOutLogger());
        logger.setLevel(HttpLoggingInterceptor.Level.HEADERS);

        spy = spy(sut);
        client = builder
                .authenticator(new CachingAuthenticatorDecorator(spy, authCache))
                .addInterceptor(new AuthenticationCacheInterceptor(authCache))
                .addNetworkInterceptor(logger)
                .build();

        unauthorizedResponse = new MockResponse()
                .setResponseCode(401)
                .addHeader("WWW-Authenticate", "Basic realm=\"myrealm\"");
        successResponse = new MockResponse().setBody("OK");
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
        assertThat(secondRequest.getHeader("Authorization")).matches("Basic dXNlcjE6dXNlcjE=");
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
        verify(spy, times(2)).authenticate(any(Route.class), any(Response.class));
        verifyNoMoreInteractions(spy);
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
        assertThat(req2.getHeader("Authorization")).isEqualTo("Basic dXNlcjE6dXNlcjE=");
        assertThat(req3.getHeader("Authorization")).isEqualTo("Basic dXNlcjI6dXNlcjE=");
    }

}

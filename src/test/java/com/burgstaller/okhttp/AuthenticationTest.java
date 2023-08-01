package com.burgstaller.okhttp;

import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;
import com.burgstaller.okhttp.digest.DigestAuthenticator;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.Options;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.http.HttpHeader;
import com.github.tomakehurst.wiremock.http.LoggedResponse;
import com.github.tomakehurst.wiremock.http.RequestMethod;
import com.github.tomakehurst.wiremock.http.trafficlistener.ConsoleNotifyingWiremockNetworkTrafficListener;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.google.common.collect.Lists;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.assertj.core.api.Condition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class AuthenticationTest {
    public static final String ACCESS_GRANTED = "access_granted";
    public static final String UNAUTHORIZED_STATE = "Unauthorized";
    public static final String PROXY_AUTHENTICATION_REQUIRED_STATE = "Proxy_Authentication_Required";

    @RegisterExtension
    static WireMockExtension wmHttp;

    static {

        wmHttp = WireMockExtension.newInstance()
                .options(
                        WireMockConfiguration.wireMockConfig()
                                .dynamicPort()
                                .networkTrafficListener(new ConsoleNotifyingWiremockNetworkTrafficListener())
                                .useChunkedTransferEncoding(Options.ChunkedEncodingPolicy.NEVER)
                )
                .build();
    }

    private String getIP() {
        try (DatagramSocket datagramSocket = new DatagramSocket()) {
            datagramSocket.connect(InetAddress.getByName("8.8.8.8"), 12345);
            return datagramSocket.getLocalAddress().getHostAddress();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("test proxy with 'basic' authentication and 'basic' authentication on website")
    public void test_proxy_with_basic_authentication_and_basic_authentication_on_website() throws IOException {


        String bodyResponse = "pong";
        WireMockRuntimeInfo wmRuntimeInfo = wmHttp.getRuntimeInfo();
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        //the test will call the proxy to try to forward the request, but wiremock won't relay.
        String baseUrl = "http://" + getIP() + ":" + wmHttp.getPort();
        String url = baseUrl + "/ping";

        String proxyUsername = "proxyuser1";
        String proxyPassword = "proxypassword1";

        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(getIP(), wmRuntimeInfo.getHttpPort()));

        BasicAuthenticator basicProxyAuthenticator = new BasicAuthenticator(
                new Credentials(proxyUsername, proxyPassword));


        String username = "user1";
        String password = "password1";

        BasicAuthenticator basicAuthenticator = new BasicAuthenticator(
                new Credentials(username, password));

        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

        final OkHttpClient client = new OkHttpClient.Builder()
                .proxy(proxy)
                .authenticator(new CachingAuthenticatorDecorator(basicAuthenticator, authCache, new DefaultRequestCacheKeyProvider()))
                .proxyAuthenticator(new CachingAuthenticatorDecorator(basicProxyAuthenticator, authCache, new DefaultProxyCacheKeyProvider()))
                .addNetworkInterceptor(new AuthenticationCacheInterceptor(authCache, new DefaultProxyCacheKeyProvider()))
                .addInterceptor(new AuthenticationCacheInterceptor(authCache, new DefaultRequestCacheKeyProvider()))
                .build();

        final Request request = new Request.Builder()
                .url(url)
                .build();

        String scenario = "Proxy with authentication";

        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(STARTED)
                        .willReturn(WireMock.aResponse()
                                .withHeader("Date", "Wed, 21 Oct 2022 05:21:23 GMT")
                                .withHeader("Proxy-Authenticate", "Basic realm=\"Access to staging site\"")
                                .withStatus(407)
                                .withStatusMessage("Proxy Authentication Required")
                        ).willSetStateTo(PROXY_AUTHENTICATION_REQUIRED_STATE)
                );
        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(PROXY_AUTHENTICATION_REQUIRED_STATE)
                        .withHeader("Proxy-Authorization", containing("Basic cHJveHl1c2VyMTpwcm94eXBhc3N3b3JkMQ=="))
                        .willReturn(WireMock.aResponse()
                                .withHeader("Date", "Wed, 21 Oct 2022 05:21:23 GMT")
                                .withHeader("WWW-Authenticate", "Basic realm=\"Access to staging site\"")
                                .withStatus(401)
                                .withStatusMessage("Unauthorized")
                        ).willSetStateTo(UNAUTHORIZED_STATE)
                );
        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(UNAUTHORIZED_STATE)
                        .withHeader("Proxy-Authorization", containing("Basic cHJveHl1c2VyMTpwcm94eXBhc3N3b3JkMQ=="))
                        .withBasicAuth(username, password)
                        .willReturn(WireMock.aResponse()
                                .withHeader("Content/Type", "text/plain")
                                .withBody(bodyResponse)
                                .withStatus(200)
                                .withStatusMessage("OK")
                        ).willSetStateTo(ACCESS_GRANTED)
                );
        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(ACCESS_GRANTED)
                        .withHeader("Proxy-Authorization", containing("Basic cHJveHl1c2VyMTpwcm94eXBhc3N3b3JkMQ=="))
                        .withBasicAuth(username, password)
                        .willReturn(WireMock.aResponse()
                                .withHeader("Content/Type", "text/plain")
                                .withBody(bodyResponse)
                                .withStatus(200)
                                .withStatusMessage("OK")
                        ).willSetStateTo(ACCESS_GRANTED)
                );
        Response myDirectResponse1 = client.newCall(request).execute();
        assertThat(myDirectResponse1.code()).isEqualTo(200);
        Response myDirectResponse2 = client.newCall(request).execute();
        assertThat(myDirectResponse2.code()).isEqualTo(200);

        Scenario scenario1 = wireMock.getScenarios().get(0);

        //check scenario
        assertThat(scenario1.getName()).isEqualTo("Proxy with authentication");
        //check its final state
        assertThat(scenario1.getState()).isEqualTo(ACCESS_GRANTED);

        List<ServeEvent> allServeEvents = wmHttp.getAllServeEvents();
        ArrayList<ServeEvent> serveEvents = Lists.newArrayList(allServeEvents);
        //events are initially sorted with the more fresh event in the first position.
        Collections.reverse(serveEvents);

        assertThat(serveEvents).hasSize(4);

        //1
        ServeEvent serveEvent1 = serveEvents.get(0);
        LoggedRequest request1 = serveEvent1.getRequest();
        assertThat(request1.getUrl()).isEqualTo("/ping");
        assertThat(request1.getMethod()).isEqualTo(RequestMethod.GET);
        LoggedResponse response1 = serveEvent1.getResponse();
        assertThat(response1.getHeaders().all()).contains(
                new HttpHeader("Date","Wed, 21 Oct 2022 05:21:23 GMT"),
                new HttpHeader("Proxy-Authenticate","Basic realm=\"Access to staging site\"")
        );
        int status1 = response1.getStatus();
        assertThat(status1).isEqualTo(407);

        //2
        ServeEvent serveEvent2 = serveEvents.get(1);
        LoggedRequest request2 = serveEvent2.getRequest();
        assertThat(request2.getUrl()).isEqualTo("/ping");
        assertThat(request2.getMethod()).isEqualTo(RequestMethod.GET);
        assertThat(request2.getHeaders().all()).contains(
                new HttpHeader("Proxy-Authorization","Basic cHJveHl1c2VyMTpwcm94eXBhc3N3b3JkMQ==")
        );
        LoggedResponse response2 = serveEvent2.getResponse();
        assertThat(response2.getHeaders().all()).contains(
                new HttpHeader("Date","Wed, 21 Oct 2022 05:21:23 GMT"),
                new HttpHeader("WWW-Authenticate","Basic realm=\"Access to staging site\"")
        );
        int status2 = response2.getStatus();
        assertThat(status2).isEqualTo(401);

        //3
        ServeEvent serveEvent3 = serveEvents.get(2);
        LoggedRequest request3 = serveEvent3.getRequest();
        assertThat(request3.getUrl()).isEqualTo("/ping");
        assertThat(request3.getMethod()).isEqualTo(RequestMethod.GET);
        assertThat(request3.getHeaders().all()).contains(
                new HttpHeader("Proxy-Authorization","Basic cHJveHl1c2VyMTpwcm94eXBhc3N3b3JkMQ=="),
                new HttpHeader("Authorization","Basic dXNlcjE6cGFzc3dvcmQx")
        );
        LoggedResponse response3 = serveEvent3.getResponse();
        assertThat(response3.getHeaders().all()).contains(
                new HttpHeader("Content/Type", "text/plain")
        );
        assertThat(response3.getBodyAsString()).isEqualTo(bodyResponse);
        int status3 = response3.getStatus();
        assertThat(status3).isEqualTo(200);

        //4
        ServeEvent serveEvent4 = serveEvents.get(3);
        LoggedRequest request4 = serveEvent4.getRequest();
        assertThat(request4.getUrl()).isEqualTo("/ping");
        assertThat(request4.getMethod()).isEqualTo(RequestMethod.GET);
        assertThat(request4.getHeaders().all()).contains(
                new HttpHeader("Proxy-Authorization","Basic cHJveHl1c2VyMTpwcm94eXBhc3N3b3JkMQ=="),
                new HttpHeader("Authorization","Basic dXNlcjE6cGFzc3dvcmQx")
        );
        LoggedResponse response4 = serveEvent4.getResponse();
        assertThat(response4.getHeaders().all()).contains(
                new HttpHeader("Content/Type", "text/plain")
        );
        assertThat(response4.getBodyAsString()).isEqualTo(bodyResponse);
        int status4 = response4.getStatus();
        assertThat(status4).isEqualTo(200);

    }

    @Test
    @DisplayName("test proxy with 'digest' authentication and 'digest' authentication on website")
    public void test_proxy_with_digest_authentication_and_digest_authentication_on_website() throws IOException {


        String bodyResponse = "pong";
        WireMockRuntimeInfo wmRuntimeInfo = wmHttp.getRuntimeInfo();
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        //the test will call the proxy to try to forward the request, but wiremock won't relay.
        String baseUrl = "http://" + getIP() + ":" + wmHttp.getPort();
        String url = baseUrl + "/ping";

        String proxyUsername = "proxyuser1";
        String proxyPassword = "proxypassword1";

        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(getIP(), wmRuntimeInfo.getHttpPort()));

        byte[] randomBytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

        Random random = mock(Random.class, withSettings().withoutAnnotations());
        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            byte[] rnd = (byte[]) args[0];
            System.arraycopy(randomBytes, 0, rnd, 0, randomBytes.length);
            return null;
        }).when(random).nextBytes(any(byte[].class));

        DigestAuthenticator digestProxyAuthenticator = new DigestAuthenticator(
                new Credentials(proxyUsername, proxyPassword), StandardCharsets.US_ASCII, random);


        String username = "user1";
        String password = "password1";

        DigestAuthenticator digestAuthenticator = new DigestAuthenticator(
                new Credentials(username, password), StandardCharsets.US_ASCII, random);

        final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

        final OkHttpClient client = new OkHttpClient.Builder()
                .proxy(proxy)
                .proxyAuthenticator(new CachingAuthenticatorDecorator(digestProxyAuthenticator, authCache, new DefaultProxyCacheKeyProvider()))
                .authenticator(new CachingAuthenticatorDecorator(digestAuthenticator, authCache, new DefaultRequestCacheKeyProvider()))
                .addNetworkInterceptor(new AuthenticationCacheInterceptor(authCache, new DefaultProxyCacheKeyProvider()))
                .addInterceptor(new AuthenticationCacheInterceptor(authCache, new DefaultRequestCacheKeyProvider()))
                .build();

        final Request request = new Request.Builder()
                .url(url)
                .build();

        String scenario = "Proxy with authentication";

        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(STARTED)
                        .willReturn(WireMock.aResponse()
                                .withHeader("Date", "Wed, 21 Oct 2022 05:21:23 GMT")
                                .withHeader("Proxy-Authenticate",
                                        "Digest " +
                                                "realm=\"Access to proxy site\"," +
                                                "qop=\"auth,auth-int\"," +
                                                "nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\"," +
                                                "opaque=\"5cdc029c403ebaf9f0171e9517f40e41\"")
                                .withStatus(407)
                                .withStatusMessage("Proxy Authentication Required")
                        ).willSetStateTo(PROXY_AUTHENTICATION_REQUIRED_STATE)
                );
        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(PROXY_AUTHENTICATION_REQUIRED_STATE)
                        .withHeader("Proxy-Authorization",
                                equalTo("Digest " +
                                        "username=\"proxyuser1\", " +
                                        "realm=\"Access to proxy site\", " +
                                        "nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\", " +
                                        "uri=\"/ping\", " +
                                        "response=\"e9920e89b8c768223a62dda432a33ab1\", " +
                                        "qop=auth, " +
                                        "nc=00000001, " +
                                        "cnonce=\"0001020304050607\", " +
                                        "algorithm=MD5, " +
                                        "opaque=\"5cdc029c403ebaf9f0171e9517f40e41\""
                                )
                        )
                        .willReturn(WireMock.aResponse()
                                .withHeader("Date", "Wed, 21 Oct 2022 05:21:23 GMT")
                                .withHeader("WWW-Authenticate", "Digest " +
                                        "realm=\"Access to web site\"," +
                                        "qop=\"auth,auth-int\"," +
                                        "nonce=\"aad55b7102dd2f0e8c99d123456fb0c011\"," +
                                        "opaque=\"5caa029c403ebaf9f3333e9517f40e66\"")
                                .withStatus(401)
                                .withStatusMessage("Unauthorized")
                        ).willSetStateTo(UNAUTHORIZED_STATE)
                );
        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(UNAUTHORIZED_STATE)
                        .withHeader("Proxy-Authorization",
                                equalTo("Digest " +
                                        "username=\"proxyuser1\", " +
                                        "realm=\"Access to proxy site\", " +
                                        "nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\", " +
                                        "uri=\"/ping\", " +
                                        "response=\"e9920e89b8c768223a62dda432a33ab1\", " +
                                        "qop=auth, " +
                                        "nc=00000001, " +
                                        "cnonce=\"0001020304050607\", " +
                                        "algorithm=MD5, " +
                                        "opaque=\"5cdc029c403ebaf9f0171e9517f40e41\""
                                )
                        )
                        .withHeader("Authorization",
                                equalTo("Digest " +
                                        "username=\"user1\", " +
                                        "realm=\"Access to web site\", " +
                                        "nonce=\"aad55b7102dd2f0e8c99d123456fb0c011\", " +
                                        "uri=\"/ping\", " +
                                        "response=\"cbe92e92eb135ebea5c11fdf80d728d4\", " +
                                        "qop=auth, " +
                                        "nc=00000001, " +
                                        "cnonce=\"0001020304050607\", " +
                                        "algorithm=MD5, " +
                                        "opaque=\"5caa029c403ebaf9f3333e9517f40e66\""
                                )
                        )
                        .willReturn(WireMock.aResponse()
                                .withHeader("Content/Type", "text/plain")
                                .withBody(bodyResponse)
                                .withStatus(200)
                                .withStatusMessage("OK")
                        ).willSetStateTo(ACCESS_GRANTED)
                );
        wireMock
                .register(WireMock.get("/ping").inScenario(scenario)
                        .whenScenarioStateIs(ACCESS_GRANTED)
                        .withHeader("Proxy-Authorization",
                                equalTo("Digest " +
                                        "username=\"proxyuser1\", " +
                                        "realm=\"Access to proxy site\", " +
                                        "nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\", " +
                                        "uri=\"/ping\", " +
                                        "response=\"ab6c6c6d8399935a747dba23f84d99e1\", " +
                                        "qop=auth, " +
                                        "nc=00000002, " +
                                        "cnonce=\"0001020304050607\", " +
                                        "algorithm=MD5, " +
                                        "opaque=\"5cdc029c403ebaf9f0171e9517f40e41\""
                                )
                        )
                        .withHeader("Authorization",
                                equalTo("Digest " +
                                        "username=\"user1\", " +
                                        "realm=\"Access to web site\", " +
                                        "nonce=\"aad55b7102dd2f0e8c99d123456fb0c011\", " +
                                        "uri=\"/ping\", " +
                                        "response=\"3855fd23f16597806e6df635bf4a40fb\", " +
                                        "qop=auth, " +
                                        "nc=00000002, " +
                                        "cnonce=\"0001020304050607\", " +
                                        "algorithm=MD5, " +
                                        "opaque=\"5caa029c403ebaf9f3333e9517f40e66\""
                                )
                        )
                        .willReturn(WireMock.aResponse()
                                .withHeader("Content/Type", "text/plain")
                                .withBody(bodyResponse)
                                .withStatus(200)
                                .withStatusMessage("OK")
                        ).willSetStateTo(ACCESS_GRANTED)
                );
        Response myResponse1 = client.newCall(request).execute();
        assertThat(myResponse1.code()).isEqualTo(200);
        Response myResponse2 = client.newCall(request).execute();
        assertThat(myResponse2.code()).isEqualTo(200);

        Scenario scenario1 = wireMock.getScenarios().get(0);

        //check scenario
        assertThat(scenario1.getName()).isEqualTo(scenario);
        //check its final state
        assertThat(scenario1.getState()).isEqualTo(ACCESS_GRANTED);

        List<ServeEvent> allServeEvents = wmHttp.getAllServeEvents();
        ArrayList<ServeEvent> serveEvents = Lists.newArrayList(allServeEvents);
        //events are initially sorted with the more fresh event in the first position.
        Collections.reverse(serveEvents);

        assertThat(serveEvents).hasSize(4);

        //1
        ServeEvent serveEvent1 = serveEvents.get(0);
        LoggedRequest request1 = serveEvent1.getRequest();
        assertThat(request1.getUrl()).isEqualTo("/ping");
        assertThat(request1.getMethod()).isEqualTo(RequestMethod.GET);
        LoggedResponse response1 = serveEvent1.getResponse();
        assertThat(response1.getHeaders().all()).contains(
                new HttpHeader("Date","Wed, 21 Oct 2022 05:21:23 GMT"),
                new HttpHeader("Proxy-Authenticate","Digest realm=\"Access to proxy site\",qop=\"auth,auth-int\",nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\",opaque=\"5cdc029c403ebaf9f0171e9517f40e41\"")
        );
        int status1 = response1.getStatus();
        assertThat(status1).isEqualTo(407);

        //2
        ServeEvent serveEvent2 = serveEvents.get(1);
        LoggedRequest request2 = serveEvent2.getRequest();
        assertThat(request2.getUrl()).isEqualTo("/ping");
        assertThat(request2.getMethod()).isEqualTo(RequestMethod.GET);
        assertThat(request2.getHeaders().all()).contains(
                new HttpHeader("Proxy-Authorization","Digest username=\"proxyuser1\", realm=\"Access to proxy site\", nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\", uri=\"/ping\", response=\"e9920e89b8c768223a62dda432a33ab1\", qop=auth, nc=00000001, cnonce=\"0001020304050607\", algorithm=MD5, opaque=\"5cdc029c403ebaf9f0171e9517f40e41\"")
        );
        LoggedResponse response2 = serveEvent2.getResponse();
        assertThat(response2.getHeaders().all()).contains(
                new HttpHeader("Date","Wed, 21 Oct 2022 05:21:23 GMT"),
                new HttpHeader("WWW-Authenticate","Digest realm=\"Access to web site\",qop=\"auth,auth-int\",nonce=\"aad55b7102dd2f0e8c99d123456fb0c011\",opaque=\"5caa029c403ebaf9f3333e9517f40e66\"")
        );
        int status2 = response2.getStatus();
        assertThat(status2).isEqualTo(401);

        //3
        ServeEvent serveEvent3 = serveEvents.get(2);
        LoggedRequest request3 = serveEvent3.getRequest();
        assertThat(request3.getUrl()).isEqualTo("/ping");
        assertThat(request3.getMethod()).isEqualTo(RequestMethod.GET);
        assertThat(request3.getHeaders().all()).contains(
                new HttpHeader("Proxy-Authorization","Digest username=\"proxyuser1\", realm=\"Access to proxy site\", nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\", uri=\"/ping\", response=\"e9920e89b8c768223a62dda432a33ab1\", qop=auth, nc=00000001, cnonce=\"0001020304050607\", algorithm=MD5, opaque=\"5cdc029c403ebaf9f0171e9517f40e41\""),
                new HttpHeader("Authorization","Digest username=\"user1\", realm=\"Access to web site\", nonce=\"aad55b7102dd2f0e8c99d123456fb0c011\", uri=\"/ping\", response=\"cbe92e92eb135ebea5c11fdf80d728d4\", qop=auth, nc=00000001, cnonce=\"0001020304050607\", algorithm=MD5, opaque=\"5caa029c403ebaf9f3333e9517f40e66\"")
        );
        LoggedResponse response3 = serveEvent3.getResponse();
        assertThat(response3.getHeaders().all()).contains(
                new HttpHeader("Content/Type", "text/plain")
        );
        assertThat(response3.getBodyAsString()).isEqualTo(bodyResponse);
        int status3 = response3.getStatus();
        assertThat(status3).isEqualTo(200);

        //4
        ServeEvent serveEvent4 = serveEvents.get(3);
        LoggedRequest request4 = serveEvent4.getRequest();
        assertThat(request4.getUrl()).isEqualTo("/ping");
        assertThat(request4.getMethod()).isEqualTo(RequestMethod.GET);
        assertThat(request4.getHeaders().all()).contains(
                new HttpHeader("Proxy-Authorization","Digest username=\"proxyuser1\", realm=\"Access to proxy site\", nonce=\"dcd98b7102dd2f0e8b11d0f615bfb0c093\", uri=\"/ping\", response=\"ab6c6c6d8399935a747dba23f84d99e1\", qop=auth, nc=00000002, cnonce=\"0001020304050607\", algorithm=MD5, opaque=\"5cdc029c403ebaf9f0171e9517f40e41\""),
                new HttpHeader("Authorization","Digest username=\"user1\", realm=\"Access to web site\", nonce=\"aad55b7102dd2f0e8c99d123456fb0c011\", uri=\"/ping\", response=\"3855fd23f16597806e6df635bf4a40fb\", qop=auth, nc=00000002, cnonce=\"0001020304050607\", algorithm=MD5, opaque=\"5caa029c403ebaf9f3333e9517f40e66\"")
        );
        LoggedResponse response4 = serveEvent4.getResponse();
        assertThat(response4.getHeaders().all()).contains(
                new HttpHeader("Content/Type", "text/plain")
        );
        assertThat(response4.getBodyAsString()).isEqualTo(bodyResponse);
        int status4 = response4.getStatus();
        assertThat(status4).isEqualTo(200);
    }


}

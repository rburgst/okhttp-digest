package com.burgstaller.okhttp.digest;

import org.junit.Before;
import org.junit.Test;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;

import static org.hamcrest.text.MatchesPattern.matchesPattern;
import static org.junit.Assert.assertThat;

public class DigestAuthenticatorTest {

    private DigestAuthenticator authenticator;

    @Before
    public void setUp() throws Exception {
        authenticator = new DigestAuthenticator(new Credentials("user1", "user1"));
    }

    @Test
    public void testAuthenticate() throws Exception {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .header("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"NnjGCdMhBQA=8ede771f94b593e46e5d0dd10b68313226c133f4\", algorithm=MD5, qop=\"auth\"")
                .build();
        Request authenticated = authenticator.authenticate(null, response);

        assertThat(authenticated.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", nonce=\"NnjGCdMhBQA=8ede771f94b593e46e5d0dd10b68313226c133f4\", uri=\"http://www\\.google\\.com/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }

    @Test
    public void testAuthenticate_withMultipleAuthResponseHeaders_shouldWork() throws IOException {
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .addHeader("WWW-Authenticate",
                        "Digest realm=\"myrealm\", nonce=\"NnjGCdMhBQA=8ede771f94b593e46e5d0dd10b68313226c133f4\", algorithm=MD5, qop=\"auth\"")
                .addHeader("WWW-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();
        Request authenticated = authenticator.authenticate(null, response);

        assertThat(authenticated.header("Authorization"),
                matchesPattern("Digest username=\"user1\", realm=\"myrealm\", nonce=\"NnjGCdMhBQA=8ede771f94b593e46e5d0dd10b68313226c133f4\", uri=\"http://www\\.google\\.com/\", response=\"[0-9a-f]+\", qop=auth, nc=00000001, cnonce=\"[0-9a-f]+\", algorithm=MD5"));
    }
}
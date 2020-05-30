package com.burgstaller.okhttp.basic;

import com.burgstaller.okhttp.digest.Credentials;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Unit test for basic authenticator.
 *
 * @author Rainer Burgstaller
 */
public class BasicAuthenticatorTest {

    private BasicAuthenticator authenticator;

    @Before
    public void setUp() throws Exception {
        authenticator = new BasicAuthenticator(new Credentials("user1", "user1"));
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
                .message("Unauthorized")
                .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                .build();
        Request authenticated = authenticator.authenticate(null, response);

        assertThat(authenticated.header("Authorization")).matches("Basic dXNlcjE6dXNlcjE=");
    }

    @Test
    public void testAuthenticate__withUtf8__shouldProperlyEncode() throws Exception {
        BasicAuthenticator utf8Authenticator = new BasicAuthenticator(new Credentials("user1", "päßwörd"), StandardCharsets.UTF_8);

        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate", "Basic realm=\"myrealm\"")
                .build();
        Request authenticated = utf8Authenticator.authenticate(null, response);

        assertThat(authenticated.header("Authorization")).matches("Basic dXNlcjE6cMOkw593w7ZyZA==");
    }

    @Test
    public void testAuthenticate_withWrongPassword_shouldNotRepeat() throws IOException {
        // given
        Request dummyRequest = new Request.Builder()
                .url("http://www.google.com")
                .header("Authorization", "Basic dXNlcjE6dXNlcjE=")
                .get()
                .build();
        Response response = new Response.Builder()
                .request(dummyRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .header("WWW-Authenticate", "Basic realm=\"DVRNVRDVS\"")
                .build();

        // when
        final Request result = authenticator.authenticate(null, response);

        // then
        assertThat(result).isNull();
    }
}

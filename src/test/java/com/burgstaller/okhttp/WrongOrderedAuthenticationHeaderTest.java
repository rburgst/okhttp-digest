package com.burgstaller.okhttp;

import org.junit.Test;

import java.util.List;

import okhttp3.Challenge;
import okhttp3.Headers;
import okhttp3.internal.http.HttpHeaders;

import static org.junit.Assert.assertEquals;

/**
 * Unit test for wrong ordered authentication header.
 */
public class WrongOrderedAuthenticationHeaderTest {
    /**
     * See: https://github.com/square/okhttp/issues/2780
     */
    @Test
    public void testWithCorrectOrder() {
        // Strict RFC 2617 header
        Headers headers = new Headers.Builder()
                .add("WWW-Authenticate", "Digest realm=\"myrealm\", nonce=\"fjalskdflwejrlaskdfjlaskdjflaksjdflkasdf\", qop=\"auth\", stale=\"FALSE\"").build();
        List<Challenge> challenges = HttpHeaders.parseChallenges(headers, "WWW-Authenticate");
        assertEquals(1, challenges.size());
        assertEquals("Digest", challenges.get(0).scheme());
        assertEquals("myrealm", challenges.get(0).realm());
    }

    @Test
    public void testWithWrongOrder() {
        // Not strict RFC 2617 header.
        Headers headers = new Headers.Builder()
                .add("WWW-Authenticate", "Digest qop=\"auth\", realm=\"myrealm\", nonce=\"fjalskdflwejrlaskdfjlaskdjflaksjdflkasdf\", stale=\"FALSE\"").build();
        List<Challenge> challenges = HttpHeaders.parseChallenges(headers, "WWW-Authenticate");
        assertEquals(1, challenges.size());

        assertEquals(1, challenges.size());
        assertEquals("Digest", challenges.get(0).scheme());
        assertEquals("myrealm", challenges.get(0).realm());
    }
}

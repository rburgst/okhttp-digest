package com.burgstaller.okhttp;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import okhttp3.Challenge;
import okhttp3.Headers;
import okhttp3.internal.http.HttpHeaders;

/**
 * Unit test for wrong ordered authentication header.
 */
public class WrongOrderedAuthenticationHeaderTest {
    /**
     * See: https://github.com/square/okhttp/issues/2780
     */
    @Test
    public void testWrongOrderedHeader() {
        // Strict RFC 2617 header
        Headers headers = new Headers.Builder()
                .add("WWW-Authenticate", "Digest realm=\"myrealm\", nonce=\"fjalskdflwejrlaskdfjlaskdjflaksjdflkasdf\", qop=\"auth\", stale=\"FALSE\"").build();
        List<Challenge> challenges = HttpHeaders.parseChallenges(headers, "WWW-Authenticate");
        Assert.assertEquals(1, challenges.size());
        Assert.assertEquals("Digest", challenges.get(0).scheme());
        Assert.assertEquals("myrealm", challenges.get(0).realm());

        // Not strict RFC 2617 header. No challenge will be found HttpHeaders.parseChallenges(...) in OkHttp 3.4.1.
        headers = new Headers.Builder()
                .add("WWW-Authenticate", "Digest qop=\"auth\", realm=\"myrealm\", nonce=\"fjalskdflwejrlaskdfjlaskdjflaksjdflkasdf\", stale=\"FALSE\"").build();
        challenges = HttpHeaders.parseChallenges(headers, "WWW-Authenticate");
        Assert.assertEquals(0, challenges.size());

        // More flexible implementation finds header
        challenges = ChallengeParser.challenges("WWW-Authenticate", headers);
        Assert.assertEquals(1, challenges.size());
        Assert.assertEquals("Digest", challenges.get(0).scheme());
        Assert.assertEquals("myrealm", challenges.get(0).realm());
    }
}

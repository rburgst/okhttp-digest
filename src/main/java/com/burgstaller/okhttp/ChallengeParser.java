package com.burgstaller.okhttp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import okhttp3.Challenge;
import okhttp3.Headers;
import okhttp3.Response;

import static java.net.HttpURLConnection.HTTP_PROXY_AUTH;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;

/**
 * Challenge parser which allows parsing of Authentication headers which don't follow RFC 2617
 * See: https://github.com/square/okhttp/issues/2780
 *
 * @author Lukas Aichbauer
 */
public final class ChallengeParser {
    private static final Pattern AUTHENTICATION_HEADER_PATTERN = Pattern.compile("(.*?) .*?realm=\"(.*?)\"", Pattern.CASE_INSENSITIVE);

    public static List<Challenge> challenges(Response response) {
        if (response.code() == HTTP_UNAUTHORIZED) {
            return challenges("WWW-Authenticate", response.headers());
        } else if (response.code() == HTTP_PROXY_AUTH) {
            return challenges("Proxy-Authenticate", response.headers());
        } else {
            return Collections.emptyList();
        }
    }

    public static List<Challenge> challenges(String header, Headers headers) {
        List<Challenge> challenges = new ArrayList<>();
        List<String> authenticationHeaders = headers.values(header);
        for (String authenticationHeader : authenticationHeaders) {
            Matcher matcher = AUTHENTICATION_HEADER_PATTERN.matcher(authenticationHeader);
            if (matcher.find()) {
                challenges.add(new Challenge(matcher.group(1), matcher.group(2)));
            }
        }
        return challenges;
    }
}

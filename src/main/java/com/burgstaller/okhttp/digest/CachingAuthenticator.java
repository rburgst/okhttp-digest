package com.burgstaller.okhttp.digest;

import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.Request;

import java.io.IOException;

/**
 * A subinterface for authenticators which support auth sessions.
 */
public interface CachingAuthenticator extends Authenticator {
    /**
     * Authenticate the new request using cached information already established from an earlier
     * authentication.
     *
     * @param request the new request to be authenticated.
     * @return the modified request with updated auth headers.
     * @throws IOException in case of a communication problem
     */
    Request authenticateWithState(Request request) throws IOException;
}

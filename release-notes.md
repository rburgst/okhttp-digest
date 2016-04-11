## v1.3

* also fixed HTTP basic authenticator to prevent ProtocolExceptions for wrong password

## v1.2

* Fixed issue where wrong password would lead to ProtocolException (too many retries)


## v1.1

* Upgraded to `okhttp 3.2.0`
* Now the authentication scheme is compared via lowercase text. This should fix servers that send
  auth challenges in different upper/lowercase form (e.g. some servers send BASIC auth scheme).
* Now also BASIC auth is cached to prevent extra roundtrips.


## v1.0

* Upgraded `okhttp` dependency to `3.0.1`. You now need to setup your `OkHttpClient` via `OkHttpClient.Builder`,
  see below


            final BasicAuthenticator basicAuthenticator = new BasicAuthenticator(credentials);
            final DigestAuthenticator digestAuthenticator = new DigestAuthenticator(credentials);

            DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder()
                    .with("Digest", digestAuthenticator)
                    .with("Basic", basicAuthenticator)
                    .build();

            client = builder
                    .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
                    .addInterceptor(new AuthenticationCacheInterceptor(authCache))
                    .addNetworkInterceptor(logger)
                    .build();

## v0.6

* Upgraded `okhttp` dependency to `2.7.0`. This is the first release that properly
 handles redirects on `PROPFIND` requests.
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
## v2.5

* republished at mavencentral under `io.github.rburgst:okhttp-digest`
* Added a null check for inputs to Credentials

## v2.4

* upgrade to okhttp 4.7.2
* add support to specify basic authentication encoding (#66) 

## v2.3

* fix exception upon preemptive proxy auth after redirect (#64) 

## v1.19

* upgrade to okhttp 3.12.6
* fix concurrent request scenarios (#62)

## v2.2

* upgrade to okhttp 4.4
* fix concurrent request scenarios (#62)

## v2.1

* upgrade to okhttp 4.3 (requires java 8 now)

## v2.0

* upgrade to okhttp 4.0.1 (requires java 8 now)

## v1.18

* upgrade to okhttp 3.11.0
* more flexible caching for multiple domains

## v1.17

* upgrade to okhttp 3.10.0

## v1.16

* upgrade to okhttp 3.9.0
* fixed proxy authentication for digest proxy

## v1.15

* fixed NPE when DigestAuthenticator was used alongside BasicAuthenticator
* now CachingAuthenticators are called in the order they were registered 

## v1.14

* improved multithreaded access
* upgraded okhttp dependency to 3.8.1

## v1.13

* converted to pure java library 
* upgraded okhttp dependency to 3.7.0

## v1.12

* fixed issues with new proxy code when no proxy was used

## v1.11 (bad release dont use)

* improved proxy authentication (not tested if it actually works)

## v1.10

* upgrade to okhttp 3.5
* improved handling of expired authentications

## v1.9

* further enhancements for multithreaded operation

## v1.8

* try to improve multithreaded operation
* reduce warning log output if used together with BASIC auth

## v1.7

* use okhttp logging rather than slf4j to prevent log warnings when 
  no slf4j implementation is available
* removed not needed manifest entries
* Fixed invalid authentication caching with multiple servers on the same host 
  
## v1.6
 
* use slf4j rather than android logging
* Fixed #12: only retry failed authentication if the nonce was stale
* upgraded to okhttp 3.4.1

## v1.5

* Fixed #10: uri parameter in authentication should not contain the hostname

## v1.4

* Fixes #8 where a changing server nonce would cause the digest authentication to try again

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

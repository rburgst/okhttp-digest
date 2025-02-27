# okhttp-digest
A digest authenticator for okhttp. Most of the code is 
ported from Apache Http Client.

### Important

This artifact has moved from jcenter to maven central! The coordinates have changed from

`com.burgstaller:okhttp-digest:<version>` to `io.github.rburgst:okhttp-digest:<version>`

For more details, see [#71](https://github.com/rburgst/okhttp-digest/issues/71).


# Usage

```java
final DigestAuthenticator authenticator = new DigestAuthenticator(new Credentials("username", "pass"));

final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
final OkHttpClient client = new OkHttpClient.Builder()
        .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
        .addInterceptor(new AuthenticationCacheInterceptor(authCache))
        .build();

String url = "http://www.google.com";
Request request = new Request.Builder()
        .url(url)
        .get()
        .build();
Response response = client.newCall(request).execute();
```

If you want to support multiple authentication schemes (including auth caching) then this should
work:

```java
final OkHttpClient.Builder builder = new OkHttpClient.Builder();
final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();

final Credentials credentials = new Credentials("username", "pass");
final BasicAuthenticator basicAuthenticator = new BasicAuthenticator(credentials);
final DigestAuthenticator digestAuthenticator = new DigestAuthenticator(credentials);

// note that all auth schemes should be registered as lowercase!
DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder()
        .with("digest", digestAuthenticator)
        .with("basic", basicAuthenticator)
        .build();

final OkHttpClient client = builder
        .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
        .addInterceptor(new AuthenticationCacheInterceptor(authCache, new DefaultRequestCacheKeyProvider()))
        .addNetworkInterceptor(logger)
        .build();
```
If you want to cache Proxy credentials, you need to add a NetworkInterceptor : 

```java
final OkHttpClient client = builder
        .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
        .addNetworkInterceptor(new AuthenticationCacheInterceptor(authCache, new DefaultProxyCacheKeyProvider()))
        .addNetworkInterceptor(logger)
        .build();
```

You can also combine Proxy AND Web site Authentication :

```java
final OkHttpClient client = builder
        .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
        .addNetworkInterceptor(new AuthenticationCacheInterceptor(authCache,new DefaultProxyCacheKeyProvider()))
        .addInterceptor(new AuthenticationCacheInterceptor(authCache,new DefaultRequestCacheKeyProvider()))        
        .addNetworkInterceptor(logger)
        .build();
```

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.rburgst/okhttp-digest/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.rburgst/okhttp-digest)
[![Build Status](https://github.com/rburgst/okhttp-digest/actions/workflows/gradle.yml/badge.svg)](https://github.com/rburgst/okhttp-digest/actions/workflows/gradle.yml)

## Use via gradle

```groovy
implementation 'io.github.rburgst:okhttp-digest:3.1.1'
```

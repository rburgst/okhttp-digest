# okhttp-digest
A digest authenticator for okhttp. Most of the code is 
ported from Apache Http Client.

# Usage

```java
        client = new OkHttpClient();
        final DigestAuthenticator authenticator = new DigestAuthenticator();
        authenticator.setCredentials(new Credentials("username", "pass"));

        final Map<String, String> authCache = new ConcurrentHashMap<>();
        client.interceptors().add(new AuthenticationCacheInterceptor(authCache));
        client.setAuthenticator(new CachingAuthenticatorDecorator(authenticator, authCache));

        Request request = new Request.Builder()
          .url(url);
          .get()
          .build();
        Response response = client.newCall(request).execute();
```

If you want to support multiple authentication schemes (including auth caching) then this should
work:

```java
        client = new OkHttpClient();
        final Map<String, String> authCache = new ConcurrentHashMap<>();

        Credentials credentials = new Credentials("username", "pass");

        final BasicAuthenticator basicAuthenticator = new BasicAuthenticator(credentials);
        final DigestAuthenticator digestAuthenticator = new DigestAuthenticator(credentials);

        DispatchingAuthenticator authenticator = new DispatchingAuthenticator.Builder()
                .with("Digest", digestAuthenticator)
                .with("Basic", basicAuthenticator)
                .build();

        client.interceptors().add(new AuthenticationCacheInterceptor(authCache));
        client.setAuthenticator(new CachingAuthenticatorDecorator(authenticator, authCache));
```

[ ![Download](https://api.bintray.com/packages/rburgst/android/okhttp-digest/images/download.svg) ](https://bintray.com/rburgst/android/okhttp-digest/_latestVersion)

## Use via gradle

```groovy
compile 'com.burgstaller:okhttp-digest:0.1'
```
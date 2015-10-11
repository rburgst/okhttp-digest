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

[ ![Download](https://api.bintray.com/packages/rburgst/android/okhttp-digest/images/download.svg) ](https://bintray.com/rburgst/android/okhttp-digest/_latestVersion)

## Use via gradle

```groovy
compile 'com.burgstaller:okhttp-digest:0.1'
```
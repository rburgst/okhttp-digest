# okhttp-digest
A digest authenticator for okhttp

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

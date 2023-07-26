package com.burgstaller.okhttp;

import okhttp3.Call;
import okhttp3.Connection;
import okhttp3.Interceptor;
import okhttp3.Request;

import java.util.concurrent.TimeUnit;

/**
 * Base class for mock interceptors.
 *
 * @author Rainer Burgstaller
 */
abstract class ChainAdapter implements Interceptor.Chain {

    private final Connection mockConnection;
    private final Request request;

    protected ChainAdapter(Request request, Connection mockConnection) {
        this.mockConnection = mockConnection;
        this.request = request;
    }

    @Override
    public Request request() {
        return request;
    }

    @Override
    public Connection connection() {
        return mockConnection;
    }

    @Override
    public Call call() {
        return null;
    }

    @Override
    public int connectTimeoutMillis() {
        return 0;
    }

    @Override
    public Interceptor.Chain withConnectTimeout(int timeout, TimeUnit unit) {
        return null;
    }

    @Override
    public int readTimeoutMillis() {
        return 0;
    }

    @Override
    public Interceptor.Chain withReadTimeout(int timeout, TimeUnit unit) {
        return null;
    }

    @Override
    public int writeTimeoutMillis() {
        return 0;
    }

    @Override
    public Interceptor.Chain withWriteTimeout(int timeout, TimeUnit unit) {
        return null;
    }
}

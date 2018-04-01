package com.burgstaller.okhttp.basic;

import okhttp3.logging.HttpLoggingInterceptor;

/**
 * Simple logger that logs all HTTP interaction to STDOUT.
 *
 * @author Rainer Burgstaller
 */
public class StdOutLogger implements HttpLoggingInterceptor.Logger {
    @Override
    public void log(String message) {
        System.out.println("HTTP: " + message);
    }
}

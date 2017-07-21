/*
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.burgstaller.okhttp.digest.fromhttpclient;


import java.util.Collection;

public class Args {
    public Args() {
    }

    public static void check(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }

    public static void check(boolean expression, String message, Object... args) {
        if (!expression) {
            throw new IllegalArgumentException(String.format(message, args));
        }
    }

    public static <T> T notNull(T argument, String name) {
        if (argument == null) {
            throw new IllegalArgumentException(name + " may not be null");
        } else {
            return argument;
        }
    }

    public static <T extends CharSequence> T notEmpty(T argument, String name) {
        if (argument == null) {
            throw new IllegalArgumentException(name + " may not be null");
        } else if (argument.length() == 0) {
            throw new IllegalArgumentException(name + " may not be empty");
        } else {
            return argument;
        }
    }

    public static <T extends CharSequence> T notBlank(T argument, String name) {
        if (argument == null) {
            throw new IllegalArgumentException(name + " may not be null");
        } else if (argument.toString().trim().length() == 0) {
            throw new IllegalArgumentException(name + " may not be blank");
        } else {
            return argument;
        }
    }

    public static <E, T extends Collection<E>> T notEmpty(T argument, String name) {
        if (argument == null) {
            throw new IllegalArgumentException(name + " may not be null");
        } else if (argument.isEmpty()) {
            throw new IllegalArgumentException(name + " may not be empty");
        } else {
            return argument;
        }
    }

    public static int positive(int n, String name) {
        if (n <= 0) {
            throw new IllegalArgumentException(name + " may not be negative or zero");
        } else {
            return n;
        }
    }

    public static long positive(long n, String name) {
        if (n <= 0L) {
            throw new IllegalArgumentException(name + " may not be negative or zero");
        } else {
            return n;
        }
    }

    public static int notNegative(int n, String name) {
        if (n < 0) {
            throw new IllegalArgumentException(name + " may not be negative");
        } else {
            return n;
        }
    }

    public static long notNegative(long n, String name) {
        if (n < 0L) {
            throw new IllegalArgumentException(name + " may not be negative");
        } else {
            return n;
        }
    }
}

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

public final class LangUtils {
    public static final int HASH_SEED = 17;
    public static final int HASH_OFFSET = 37;

    private LangUtils() {
    }

    public static int hashCode(int seed, int hashcode) {
        return seed * 37 + hashcode;
    }

    public static int hashCode(int seed, boolean b) {
        return hashCode(seed, b?1:0);
    }

    public static int hashCode(int seed, Object obj) {
        return hashCode(seed, obj != null?obj.hashCode():0);
    }

    public static boolean equals(Object obj1, Object obj2) {
        return obj1 == null?obj2 == null:obj1.equals(obj2);
    }

    public static boolean equals(Object[] a1, Object[] a2) {
        if(a1 == null) {
            return a2 == null;
        } else if(a2 != null && a1.length == a2.length) {
            for(int i = 0; i < a1.length; ++i) {
                if(!equals(a1[i], a2[i])) {
                    return false;
                }
            }

            return true;
        } else {
            return false;
        }
    }
}

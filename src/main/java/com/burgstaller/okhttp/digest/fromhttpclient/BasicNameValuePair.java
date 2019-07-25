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

import java.io.Serializable;


public class BasicNameValuePair implements NameValuePair, Cloneable, Serializable {
    private static final long serialVersionUID = -6437800749411518984L;
    private final String name;
    private final String value;

    public BasicNameValuePair(String name, String value) {
        if(name == null) {
            throw new IllegalArgumentException("Name may not be null");
        } else {
            this.name = name;
            this.value = value;
        }
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public String toString() {
        if(this.value == null) {
            return this.name;
        } else {
            int len = this.name.length() + 1 + this.value.length();
            StringBuilder buffer = new StringBuilder(len);
            buffer.append(this.name);
            buffer.append("=");
            buffer.append(this.value);
            return buffer.toString();
        }
    }

    public boolean equals(Object object) {
        if(object == null) {
            return false;
        } else if(this == object) {
            return true;
        } else if(!(object instanceof NameValuePair)) {
            return false;
        } else {
            BasicNameValuePair that = (BasicNameValuePair)object;
            return this.name.equals(that.name) && (this.value == that.value) ||
                (this.value != null && this.value.equals(that.value));
        }
    }

    public int hashCode() {
        byte hash = 17;
        int hash1 = LangUtils.hashCode(hash, this.name);
        hash1 = LangUtils.hashCode(hash1, this.value);
        return hash1;
    }

    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}

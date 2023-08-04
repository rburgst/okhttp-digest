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


public class BasicHeaderElement implements HeaderElement, Cloneable {
    private final String name;
    private final String value;
    private final NameValuePair[] parameters;

    public BasicHeaderElement(String name, String value, NameValuePair[] parameters) {
        if (name == null) {
            throw new IllegalArgumentException("Name may not be null");
        } else {
            this.name = name;
            this.value = value;
            if (parameters != null) {
                this.parameters = parameters;
            } else {
                this.parameters = new NameValuePair[0];
            }

        }
    }

    public BasicHeaderElement(String name, String value) {
        this(name, value, null);
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public NameValuePair[] getParameters() {
        return this.parameters.clone();
    }

    public int getParameterCount() {
        return this.parameters.length;
    }

    public NameValuePair getParameter(int index) {
        return this.parameters[index];
    }

    public NameValuePair getParameterByName(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Name may not be null");
        } else {
            NameValuePair found = null;

            for (int i = 0; i < this.parameters.length; ++i) {
                NameValuePair current = this.parameters[i];
                if (current.getName().equalsIgnoreCase(name)) {
                    found = current;
                    break;
                }
            }

            return found;
        }
    }

    public boolean equals(Object object) {
        if (object == null) {
            return false;
        } else if (this == object) {
            return true;
        } else if (!(object instanceof HeaderElement)) {
            return false;
        } else {
            BasicHeaderElement that = (BasicHeaderElement) object;
            return this.name.equals(that.name) && LangUtils.equals(this.value, that.value) && LangUtils.equals(this.parameters, that.parameters);
        }
    }

    public int hashCode() {
        byte hash = 17;
        int var3 = LangUtils.hashCode(hash, this.name);
        var3 = LangUtils.hashCode(var3, this.value);

        for (int i = 0; i < this.parameters.length; ++i) {
            var3 = LangUtils.hashCode(var3, this.parameters[i]);
        }

        return var3;
    }

    public String toString() {
        StringBuilder buffer = new StringBuilder(64);
        buffer.append(this.name);
        if (this.value != null) {
            buffer.append("=");
            buffer.append(this.value);
        }

        for (int i = 0; i < this.parameters.length; ++i) {
            buffer.append("; ");
            buffer.append(this.parameters[i]);
        }

        return buffer.toString();
    }

    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}

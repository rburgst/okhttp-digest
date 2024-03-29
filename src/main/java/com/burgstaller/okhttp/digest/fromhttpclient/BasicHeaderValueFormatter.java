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

/**
 * Helper class for formatting headers.
 */
public class BasicHeaderValueFormatter {
    public static final BasicHeaderValueFormatter DEFAULT = new BasicHeaderValueFormatter();

    public StringBuilder formatNameValuePair(StringBuilder charBuffer, NameValuePair nvp, boolean quote) {

        charBuffer.append(nvp.getName());
        String value = nvp.getValue();
        if (value != null) {
            charBuffer.append('=');
            this.doFormatValue(charBuffer, value, quote);
        }

        return charBuffer;
    }

    protected void doFormatValue(StringBuilder buffer, String value, boolean quote) {
        boolean quoteFlag = quote;
        int i;
        if (!quote) {
            for (i = 0; i < value.length() && !quoteFlag; ++i) {
                quoteFlag = this.isSeparator(value.charAt(i));
            }
        }

        if (quoteFlag) {
            buffer.append('\"');
        }

        for (i = 0; i < value.length(); ++i) {
            char ch = value.charAt(i);
            if (this.isUnsafe(ch)) {
                buffer.append('\\');
            }

            buffer.append(ch);
        }

        if (quoteFlag) {
            buffer.append('\"');
        }

    }


    protected boolean isSeparator(char ch) {
        return " ;,:@()<>\\\"/[]?={}\t".indexOf(ch) >= 0;
    }

    protected boolean isUnsafe(char ch) {
        return "\"\\".indexOf(ch) >= 0;
    }
}

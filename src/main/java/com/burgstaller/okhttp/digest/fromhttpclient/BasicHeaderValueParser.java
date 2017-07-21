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

import java.util.ArrayList;

public class BasicHeaderValueParser {
    /** @deprecated */
    @Deprecated
    public static final BasicHeaderValueParser DEFAULT = new BasicHeaderValueParser();
    public static final BasicHeaderValueParser INSTANCE = new BasicHeaderValueParser();
    private static final char PARAM_DELIMITER = ';';
    private static final char ELEM_DELIMITER = ',';
    private static final char[] ALL_DELIMITERS = new char[]{';', ','};

    public BasicHeaderValueParser() {
    }

    public static HeaderElement[] parseElements(String value, HeaderValueParser parser) throws ParseException {
        Args.notNull(value, "Value");
        CharArrayBuffer buffer = new CharArrayBuffer(value.length());
        buffer.append(value);
        ParserCursor cursor = new ParserCursor(0, value.length());
        return ((HeaderValueParser)(parser != null?parser:INSTANCE)).parseElements(buffer, cursor);
    }

    public HeaderElement[] parseElements(CharArrayBuffer buffer, ParserCursor cursor) {
        Args.notNull(buffer, "Char array buffer");
        Args.notNull(cursor, "Parser cursor");
        ArrayList elements = new ArrayList();

        while(true) {
            HeaderElement element;
            do {
                if(cursor.atEnd()) {
                    return (HeaderElement[])elements.toArray(new HeaderElement[elements.size()]);
                }

                element = this.parseHeaderElement(buffer, cursor);
            } while(element.getName().length() == 0 && element.getValue() == null);

            elements.add(element);
        }
    }

    public static HeaderElement parseHeaderElement(String value, HeaderValueParser parser) throws ParseException {
        Args.notNull(value, "Value");
        CharArrayBuffer buffer = new CharArrayBuffer(value.length());
        buffer.append(value);
        ParserCursor cursor = new ParserCursor(0, value.length());
        return ((HeaderValueParser)(parser != null?parser:INSTANCE)).parseHeaderElement(buffer, cursor);
    }

    public HeaderElement parseHeaderElement(CharArrayBuffer buffer, ParserCursor cursor) {
        Args.notNull(buffer, "Char array buffer");
        Args.notNull(cursor, "Parser cursor");
        NameValuePair nvp = this.parseNameValuePair(buffer, cursor);
        NameValuePair[] params = null;
        if(!cursor.atEnd()) {
            char ch = buffer.charAt(cursor.getPos() - 1);
            if(ch != 44) {
                params = this.parseParameters(buffer, cursor);
            }
        }

        return this.createHeaderElement(nvp.getName(), nvp.getValue(), params);
    }

    protected HeaderElement createHeaderElement(String name, String value, NameValuePair[] params) {
        return new BasicHeaderElement(name, value, params);
    }

    public static NameValuePair[] parseParameters(String value, HeaderValueParser parser) throws ParseException {
        Args.notNull(value, "Value");
        CharArrayBuffer buffer = new CharArrayBuffer(value.length());
        buffer.append(value);
        ParserCursor cursor = new ParserCursor(0, value.length());
        return ((HeaderValueParser)(parser != null?parser:INSTANCE)).parseParameters(buffer, cursor);
    }

    public NameValuePair[] parseParameters(CharArrayBuffer buffer, ParserCursor cursor) {
        Args.notNull(buffer, "Char array buffer");
        Args.notNull(cursor, "Parser cursor");
        int pos = cursor.getPos();

        for(int indexTo = cursor.getUpperBound(); pos < indexTo; ++pos) {
            char params = buffer.charAt(pos);
            if(!HTTP.isWhitespace(params)) {
                break;
            }
        }

        cursor.updatePos(pos);
        if(cursor.atEnd()) {
            return new NameValuePair[0];
        } else {
            ArrayList var8 = new ArrayList();

            while(!cursor.atEnd()) {
                NameValuePair param = this.parseNameValuePair(buffer, cursor);
                var8.add(param);
                char ch = buffer.charAt(cursor.getPos() - 1);
                if(ch == 44) {
                    break;
                }
            }

            return (NameValuePair[])var8.toArray(new NameValuePair[var8.size()]);
        }
    }

    public static NameValuePair parseNameValuePair(String value, HeaderValueParser parser) throws ParseException {
        Args.notNull(value, "Value");
        CharArrayBuffer buffer = new CharArrayBuffer(value.length());
        buffer.append(value);
        ParserCursor cursor = new ParserCursor(0, value.length());
        return ((HeaderValueParser)(parser != null?parser:INSTANCE)).parseNameValuePair(buffer, cursor);
    }

    public NameValuePair parseNameValuePair(CharArrayBuffer buffer, ParserCursor cursor) {
        return this.parseNameValuePair(buffer, cursor, ALL_DELIMITERS);
    }

    private static boolean isOneOf(char ch, char[] chs) {
        if(chs != null) {
            char[] arr$ = chs;
            int len$ = chs.length;

            for(int i$ = 0; i$ < len$; ++i$) {
                char ch2 = arr$[i$];
                if(ch == ch2) {
                    return true;
                }
            }
        }

        return false;
    }

    public NameValuePair parseNameValuePair(CharArrayBuffer buffer, ParserCursor cursor, char[] delimiters) {
        Args.notNull(buffer, "Char array buffer");
        Args.notNull(cursor, "Parser cursor");
        boolean terminated = false;
        int pos = cursor.getPos();
        int indexFrom = cursor.getPos();

        int indexTo;
        for(indexTo = cursor.getUpperBound(); pos < indexTo; ++pos) {
            char value = buffer.charAt(pos);
            if(value == 61) {
                break;
            }

            if(isOneOf(value, delimiters)) {
                terminated = true;
                break;
            }
        }

        String name;
        if(pos == indexTo) {
            terminated = true;
            name = buffer.substringTrimmed(indexFrom, indexTo);
        } else {
            name = buffer.substringTrimmed(indexFrom, pos);
            ++pos;
        }

        if(terminated) {
            cursor.updatePos(pos);
            return this.createNameValuePair(name, (String)null);
        } else {
            int i1 = pos;
            boolean qouted = false;

            for(boolean escaped = false; pos < indexTo; ++pos) {
                char i2 = buffer.charAt(pos);
                if(i2 == 34 && !escaped) {
                    qouted = !qouted;
                }

                if(!qouted && !escaped && isOneOf(i2, delimiters)) {
                    terminated = true;
                    break;
                }

                if(escaped) {
                    escaped = false;
                } else {
                    escaped = qouted && i2 == 92;
                }
            }

            int var15;
            for(var15 = pos; i1 < var15 && HTTP.isWhitespace(buffer.charAt(i1)); ++i1) {
                ;
            }

            while(var15 > i1 && HTTP.isWhitespace(buffer.charAt(var15 - 1))) {
                --var15;
            }

            if(var15 - i1 >= 2 && buffer.charAt(i1) == 34 && buffer.charAt(var15 - 1) == 34) {
                ++i1;
                --var15;
            }

            String var14 = buffer.substring(i1, var15);
            if(terminated) {
                ++pos;
            }

            cursor.updatePos(pos);
            return this.createNameValuePair(name, var14);
        }
    }

    protected NameValuePair createNameValuePair(String name, String value) {
        return new BasicNameValuePair(name, value);
    }
    public static boolean isWhitespace(char ch) {
        return ch == 32 || ch == 9 || ch == 13 || ch == 10;
    }

}

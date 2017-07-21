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


public final class CharArrayBuffer {
    private char[] buffer;
    private int len;

    public CharArrayBuffer(int capacity) {
        if(capacity < 0) {
            throw new IllegalArgumentException("Buffer capacity may not be negative");
        } else {
            this.buffer = new char[capacity];
        }
    }

    private void expand(int newlen) {
        char[] newbuffer = new char[Math.max(this.buffer.length << 1, newlen)];
        System.arraycopy(this.buffer, 0, newbuffer, 0, this.len);
        this.buffer = newbuffer;
    }

    public void append(char[] b, int off, int len) {
        if(b != null) {
            if(off >= 0 && off <= b.length && len >= 0 && off + len >= 0 && off + len <= b.length) {
                if(len != 0) {
                    int newlen = this.len + len;
                    if(newlen > this.buffer.length) {
                        this.expand(newlen);
                    }

                    System.arraycopy(b, off, this.buffer, this.len, len);
                    this.len = newlen;
                }
            } else {
                throw new IndexOutOfBoundsException();
            }
        }
    }

    public void append(String str) {
        if(str == null) {
            str = "null";
        }

        int strlen = str.length();
        int newlen = this.len + strlen;
        if(newlen > this.buffer.length) {
            this.expand(newlen);
        }

        str.getChars(0, strlen, this.buffer, this.len);
        this.len = newlen;
    }

    public void append(CharArrayBuffer b, int off, int len) {
        if(b != null) {
            this.append(b.buffer, off, len);
        }
    }

    public void append(CharArrayBuffer b) {
        if(b != null) {
            this.append((char[])b.buffer, 0, b.len);
        }
    }

    public void append(char ch) {
        int newlen = this.len + 1;
        if(newlen > this.buffer.length) {
            this.expand(newlen);
        }

        this.buffer[this.len] = ch;
        this.len = newlen;
    }

    public void append(byte[] b, int off, int len) {
        if(b != null) {
            if(off >= 0 && off <= b.length && len >= 0 && off + len >= 0 && off + len <= b.length) {
                if(len != 0) {
                    int oldlen = this.len;
                    int newlen = oldlen + len;
                    if(newlen > this.buffer.length) {
                        this.expand(newlen);
                    }

                    int i1 = off;

                    for(int i2 = oldlen; i2 < newlen; ++i2) {
                        this.buffer[i2] = (char)(b[i1] & 255);
                        ++i1;
                    }

                    this.len = newlen;
                }
            } else {
                throw new IndexOutOfBoundsException();
            }
        }
    }

//    public void append(ByteArrayBuffer b, int off, int len) {
//        if(b != null) {
//            this.append(b.buffer(), off, len);
//        }
//    }

    public void append(Object obj) {
        this.append(String.valueOf(obj));
    }

    public void clear() {
        this.len = 0;
    }

    public char[] toCharArray() {
        char[] b = new char[this.len];
        if(this.len > 0) {
            System.arraycopy(this.buffer, 0, b, 0, this.len);
        }

        return b;
    }

    public char charAt(int i) {
        return this.buffer[i];
    }

    public char[] buffer() {
        return this.buffer;
    }

    public int capacity() {
        return this.buffer.length;
    }

    public int length() {
        return this.len;
    }

    public void ensureCapacity(int required) {
        if(required > 0) {
            int available = this.buffer.length - this.len;
            if(required > available) {
                this.expand(this.len + required);
            }

        }
    }

    public void setLength(int len) {
        if(len >= 0 && len <= this.buffer.length) {
            this.len = len;
        } else {
            throw new IndexOutOfBoundsException();
        }
    }

    public boolean isEmpty() {
        return this.len == 0;
    }

    public boolean isFull() {
        return this.len == this.buffer.length;
    }

    public int indexOf(int ch, int beginIndex, int endIndex) {
        if(beginIndex < 0) {
            beginIndex = 0;
        }

        if(endIndex > this.len) {
            endIndex = this.len;
        }

        if(beginIndex > endIndex) {
            return -1;
        } else {
            for(int i = beginIndex; i < endIndex; ++i) {
                if(this.buffer[i] == ch) {
                    return i;
                }
            }

            return -1;
        }
    }

    public int indexOf(int ch) {
        return this.indexOf(ch, 0, this.len);
    }

    public String substring(int beginIndex, int endIndex) {
        if(beginIndex < 0) {
            throw new IndexOutOfBoundsException();
        } else if(endIndex > this.len) {
            throw new IndexOutOfBoundsException();
        } else if(beginIndex > endIndex) {
            throw new IndexOutOfBoundsException();
        } else {
            return new String(this.buffer, beginIndex, endIndex - beginIndex);
        }
    }

    public String substringTrimmed(int beginIndex, int endIndex) {
        if(beginIndex < 0) {
            throw new IndexOutOfBoundsException();
        } else if(endIndex > this.len) {
            throw new IndexOutOfBoundsException();
        } else if(beginIndex > endIndex) {
            throw new IndexOutOfBoundsException();
        } else {
            while(beginIndex < endIndex && HTTP.isWhitespace(this.buffer[beginIndex])) {
                ++beginIndex;
            }

            while(endIndex > beginIndex && HTTP.isWhitespace(this.buffer[endIndex - 1])) {
                --endIndex;
            }

            return new String(this.buffer, beginIndex, endIndex - beginIndex);
        }
    }

    public String toString() {
        return new String(this.buffer, 0, this.len);
    }
}

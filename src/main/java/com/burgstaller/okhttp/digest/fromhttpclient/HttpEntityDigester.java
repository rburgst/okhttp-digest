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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import okio.Buffer;
import okio.BufferedSink;
import okio.ByteString;
import okio.Source;
import okio.Timeout;

public class HttpEntityDigester implements BufferedSink {

    private final MessageDigest digester;
    private boolean closed;
    private byte[] digest;
    Buffer buffer;

    public HttpEntityDigester(final MessageDigest digester) {
        super();
        this.digester = digester;
        this.digester.reset();
        this.buffer = new Buffer();
    }


    @Override
    public Buffer buffer() {
        return buffer;
    }

    @Override
    public BufferedSink write(ByteString byteString) throws IOException {
        this.digester.update(byteString.toByteArray());
        return this;
    }

    @Override
    public BufferedSink write(byte[] source) throws IOException {
        this.digester.update(source);
        return this;
    }

    @Override
    public BufferedSink write(byte[] source, int offset, int byteCount) throws IOException {
        this.digester.update(source, offset, byteCount);
        return this;
    }

    @Override
    public long writeAll(Source source) throws IOException {
        return 0;
    }

    @Override
    public BufferedSink write(Source source, long byteCount) throws IOException {
        if (this.closed) {
            throw new IOException("Stream has been already closed");
        }
//        this.digester.update(b, off, len);

        return null;
    }

    @Override
    public BufferedSink writeUtf8(String string) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeUtf8(String string, int beginIndex, int endIndex) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeUtf8CodePoint(int codePoint) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeString(String string, Charset charset) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeString(String string, int beginIndex, int endIndex, Charset charset) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeByte(int b) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeShort(int s) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeShortLe(int s) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeInt(int i) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeIntLe(int i) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeLong(long v) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeLongLe(long v) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeDecimalLong(long v) throws IOException {
        return null;
    }

    @Override
    public BufferedSink writeHexadecimalUnsignedLong(long v) throws IOException {
        return null;
    }

    @Override
    public BufferedSink emitCompleteSegments() throws IOException {
        return null;
    }

    @Override
    public BufferedSink emit() throws IOException {
        return this;
    }

    @Override public OutputStream outputStream() {
        return new OutputStream() {
            @Override public void write(int b) throws IOException {
                if (closed) throw new IOException("closed");
                buffer.writeByte((byte) b);
                emitCompleteSegments();
            }

            @Override public void write(byte[] data, int offset, int byteCount) throws IOException {
                if (closed) throw new IOException("closed");
                buffer.write(data, offset, byteCount);
                emitCompleteSegments();
            }

            @Override public void flush() throws IOException {
                // For backwards compatibility, a flush() on a closed stream is a no-op.
                if (!closed) {
                    HttpEntityDigester.this.flush();
                }
            }

            @Override public void close() throws IOException {
                HttpEntityDigester.this.close();
            }

            @Override public String toString() {
                return HttpEntityDigester.this + ".outputStream()";
            }
        };
    }

    @Override
    public void write(Buffer source, long byteCount) throws IOException {

    }

    @Override
    public void flush() throws IOException {

    }

    @Override
    public Timeout timeout() {
        return null;
    }

    @Override
    public void close() throws IOException {
        if (this.closed) {
            return;
        }
        this.closed = true;
        this.digest = this.digester.digest();
        buffer.close();
    }

    public byte[] getDigest() {
        return this.digest;
    }

}
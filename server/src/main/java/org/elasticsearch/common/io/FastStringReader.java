/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.elasticsearch.common.io;

import java.io.IOException;

public class FastStringReader extends CharSequenceReader {

    private String str;
    private int length;
    private int next = 0;
    private int mark = 0;

    public FastStringReader(String s) {
        this.str = s;
        this.length = s.length();
    }

    private void ensureOpen() throws IOException {
        if (length == -1) {
            throw new IOException("Stream closed");
        }
    }

    public int length() {
        return length;
    }

    public char charAt(int index) {
        return str.charAt(index);
    }

    public CharSequence subSequence(int start, int end) {
        return str.subSequence(start, end);
    }

    public int read() throws IOException {
        ensureOpen();
        if (next >= length) {
            return -1;
        }
        return str.charAt(next++);
    }

    public int read(char cbuf[], int off, int len) throws IOException {
        ensureOpen();
        if (len == 0) {
            return 0;
        }
        if (next >= length) {
            return -1;
        }
        int n = Math.min(length - next, len);
        str.getChars(next, next + n, cbuf, off);
        next += n;
        return n;
    }

    public long skip(long ns) throws IOException {
        ensureOpen();
        if (next >= length) {
            return 0;
        }
        long n = Math.min(length - next, ns);
        n = Math.max(-next, n);
        next += n;
        return n;
    }

    public boolean ready() throws IOException {
        ensureOpen();
        return true;
    }

    public boolean markSupported() {
        return true;
    }

    public void mark(int readAheadLimit) throws IOException {
        if (readAheadLimit < 0) {
            throw new IllegalArgumentException("Read-ahead limit < 0");
        }
        ensureOpen();
        mark = next;
    }

    public void reset() throws IOException {
        ensureOpen();
        next = mark;
    }

    public void close() {
        length = -1;
    }

    public String toString() {
        return str;
    }
}

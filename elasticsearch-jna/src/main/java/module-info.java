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
module org.xbib.elasticsearch.jna {
    exports com.sun.jna;
    exports com.sun.jna.ptr;
    exports com.sun.jna.win32;

    // allow native library loading
    opens com.sun.jna.aix.ppc;
    opens com.sun.jna.aix.ppc64;
    opens com.sun.jna.darwin;
    opens com.sun.jna.freebsd.x32;
    opens com.sun.jna.freebsd.x64;
    opens com.sun.jna.linux.aarch64;
    opens com.sun.jna.linux.arm;
    opens com.sun.jna.linux.armel;
    opens com.sun.jna.linux.mips64el;
    opens com.sun.jna.linux.ppc;
    opens com.sun.jna.linux.ppc64le;
    opens com.sun.jna.linux.s390x;
    opens com.sun.jna.linux.x32;
    opens com.sun.jna.linux.x64;
    opens com.sun.jna.openbsd.x32;
    opens com.sun.jna.openbsd.x64;
    opens com.sun.jna.sunos.sparc;
    opens com.sun.jna.sunos.sparcv9;
    opens com.sun.jna.sunos.x32;
    opens com.sun.jna.sunos.x64;
    opens com.sun.jna.win32.x32;
    opens com.sun.jna.win32.x64;

    //requires java.desktop; // we removed java awt in com.sun.jna.Native
    requires java.logging;
}

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

import org.elasticsearch.common.xcontent.XContentElasticsearchExtension;

module org.xbib.elasticsearch.server {
    exports org.elasticsearch;

    // avoid Exception reading field 'rlim_cur' in class org.elasticsearch.bootstrap.JNACLibrary$Rlimit
    exports org.elasticsearch.bootstrap to org.xbib.elasticsearch.jna;

    // ES module/plugins need access to Elasticsearch packages
    exports org.elasticsearch.action;
    exports org.elasticsearch.action.support;
    exports org.elasticsearch.client;
    exports org.elasticsearch.client.node;
    exports org.elasticsearch.client.support;
    exports org.elasticsearch.client.transport;
    exports org.elasticsearch.cluster;
    exports org.elasticsearch.cluster.metadata;
    exports org.elasticsearch.cluster.node;
    exports org.elasticsearch.cluster.routing;
    exports org.elasticsearch.cluster.routing.allocation;
    exports org.elasticsearch.cluster.service;
    exports org.elasticsearch.common;
    exports org.elasticsearch.common.blobstore;
    exports org.elasticsearch.common.breaker;
    exports org.elasticsearch.common.bytes;
    exports org.elasticsearch.common.collect;
    exports org.elasticsearch.common.component;
    exports org.elasticsearch.common.compress;
    exports org.elasticsearch.common.document;
    exports org.elasticsearch.common.geo;
    exports org.elasticsearch.common.geo.builders;
    exports org.elasticsearch.common.geo.parsers;
    exports org.elasticsearch.common.hash;
    exports org.elasticsearch.common.inject;
    exports org.elasticsearch.common.inject.assistedinject;
    exports org.elasticsearch.common.inject.binder;
    exports org.elasticsearch.common.inject.matcher;
    exports org.elasticsearch.common.inject.multibindings;
    exports org.elasticsearch.common.inject.name;
    exports org.elasticsearch.common.inject.spi;
    exports org.elasticsearch.common.inject.util;
    exports org.elasticsearch.common.io;
    exports org.elasticsearch.common.io.stream;
    exports org.elasticsearch.common.joda;
    exports org.elasticsearch.common.lease;
    exports org.elasticsearch.common.logging;
    exports org.elasticsearch.common.lucene;
    exports org.elasticsearch.common.lucene.all;
    exports org.elasticsearch.common.lucene.index;
    exports org.elasticsearch.common.lucene.search;
    exports org.elasticsearch.common.lucene.search.function;
    exports org.elasticsearch.common.lucene.store;
    exports org.elasticsearch.common.lucene.uid;
    exports org.elasticsearch.common.metrics;
    exports org.elasticsearch.common.network;
    exports org.elasticsearch.common.path;
    exports org.elasticsearch.common.recycler;
    exports org.elasticsearch.common.regex;
    exports org.elasticsearch.common.rounding;
    exports org.elasticsearch.common.settings;
    exports org.elasticsearch.common.text;
    exports org.elasticsearch.common.transport;
    exports org.elasticsearch.common.unit;
    exports org.elasticsearch.common.util;
    exports org.elasticsearch.common.util.concurrent;
    exports org.elasticsearch.common.util.iterable;
    exports org.elasticsearch.common.util.set;
    exports org.elasticsearch.common.xcontent;
    exports org.elasticsearch.common.xcontent.cbor;
    exports org.elasticsearch.common.xcontent.json;
    exports org.elasticsearch.common.xcontent.smile;
    exports org.elasticsearch.common.xcontent.yaml;
    exports org.elasticsearch.discovery;
    exports org.elasticsearch.discovery.single;
    exports org.elasticsearch.discovery.zen;
    exports org.elasticsearch.env;
    exports org.elasticsearch.gateway;
    exports org.elasticsearch.http;
    exports org.elasticsearch.index;
    exports org.elasticsearch.index.analysis;
    exports org.elasticsearch.index.mapper;
    exports org.elasticsearch.index.search;
    exports org.elasticsearch.index.settings;
    exports org.elasticsearch.index.shard;
    exports org.elasticsearch.index.similarity;
    exports org.elasticsearch.index.snapshots;
    exports org.elasticsearch.index.snapshots.blobstore;
    exports org.elasticsearch.index.store;
    exports org.elasticsearch.index.termvectors;
    exports org.elasticsearch.index.translog;
    exports org.elasticsearch.index.warmer;
    exports org.elasticsearch.indices.analysis;
    exports org.elasticsearch.indices.breaker;
    exports org.elasticsearch.indices.cluster;
    exports org.elasticsearch.indices.fielddata.cache;
    exports org.elasticsearch.indices.flush;
    exports org.elasticsearch.indices.mapper;
    exports org.elasticsearch.indices.recovery;
    exports org.elasticsearch.indices.store;
    exports org.elasticsearch.ingest;
    exports org.elasticsearch.monitor;
    exports org.elasticsearch.monitor.fs;
    exports org.elasticsearch.monitor.jvm;
    exports org.elasticsearch.monitor.os;
    exports org.elasticsearch.monitor.process;
    exports org.elasticsearch.node;
    exports org.elasticsearch.persistent;
    exports org.elasticsearch.persistent.decider;
    exports org.elasticsearch.plugins;
    exports org.elasticsearch.plugins.spi;
    exports org.elasticsearch.repositories;
    exports org.elasticsearch.repositories.blobstore;
    exports org.elasticsearch.repositories.fs;
    exports org.elasticsearch.rest;
    exports org.elasticsearch.script;
    exports org.elasticsearch.search;
    exports org.elasticsearch.snapshots;
    exports org.elasticsearch.tasks;
    exports org.elasticsearch.threadpool;
    exports org.elasticsearch.transport;
    exports org.elasticsearch.usage;
    exports org.elasticsearch.watcher;

    provides org.elasticsearch.common.xcontent.XContentBuilderExtension
            with XContentElasticsearchExtension;

    requires jdk.management;
    requires org.xbib.elasticsearch.jna;
    requires org.xbib.elasticsearch.log4j;
    requires org.xbib.elasticsearch.classloader;
    requires org.xbib.elasticsearch.securesm;
    requires org.xbib.elasticsearch.joda;
    requires org.xbib.elasticsearch.jts;
    requires org.xbib.elasticsearch.spatial4j;
    requires org.xbib.elasticsearch.lucene;
    requires org.xbib.elasticsearch.hdrhistogram;
    requires org.xbib.elasticsearch.hppc;
    requires org.xbib.elasticsearch.joptsimple;
    requires org.xbib.elasticsearch.tdigest;
    requires org.xbib.elasticsearch.jackson;

    uses org.elasticsearch.common.xcontent.XContentBuilderExtension;

}

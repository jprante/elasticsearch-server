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

module org.xbib.elasticsearch.server.test {

    exports org.elasticsearch.test;
    exports org.elasticsearch.test.action;
    exports org.elasticsearch.test.action.admin;
    exports org.elasticsearch.test.action.admin.cluster.allocation;
    exports org.elasticsearch.test.action.admin.cluster.health;
    exports org.elasticsearch.test.action.admin.cluster.node.tasks;
    exports org.elasticsearch.test.action.admin.cluster.node.stats;
    exports org.elasticsearch.test.action.admin.cluster.repositories;
    exports org.elasticsearch.test.action.admin.cluster.reroute;
    exports org.elasticsearch.test.action.admin.cluster.settings;
    exports org.elasticsearch.test.action.admin.cluster.shards;
    exports org.elasticsearch.test.action.admin.cluster.snapshots;
    exports org.elasticsearch.test.action.admin.cluster.snapshots.status;
    exports org.elasticsearch.test.action.admin.cluster.state;
    exports org.elasticsearch.test.action.admin.cluster.stats;
    exports org.elasticsearch.test.action.admin.cluster.storedscripts;
    exports org.elasticsearch.test.action.admin.cluster.tasks;
    exports org.elasticsearch.test.action.admin.indices;
    exports org.elasticsearch.test.action.admin.indices.aliases;
    exports org.elasticsearch.test.action.admin.indices.analyze;
    exports org.elasticsearch.test.action.admin.indices.cache.clear;
    exports org.elasticsearch.test.action.admin.indices.close;
    exports org.elasticsearch.test.action.admin.indices.create;
    exports org.elasticsearch.test.action.admin.indices.delete;
    exports org.elasticsearch.test.action.admin.indices.exists;
    exports org.elasticsearch.test.action.admin.indices.flush;
    exports org.elasticsearch.test.action.admin.indices.forcemerge;
    exports org.elasticsearch.test.action.admin.indices.get;
    exports org.elasticsearch.test.action.admin.indices.mapping.get;
    exports org.elasticsearch.test.action.admin.indices.mapping.put;
    exports org.elasticsearch.test.action.admin.indices.open;
    exports org.elasticsearch.test.action.admin.indices.refresh;
    exports org.elasticsearch.test.action.admin.indices.rollover;
    exports org.elasticsearch.test.action.admin.indices.segments;
    exports org.elasticsearch.test.action.admin.indices.settings.put;
    exports org.elasticsearch.test.action.admin.indices.shards;
    exports org.elasticsearch.test.action.admin.indices.shrink;
    exports org.elasticsearch.test.action.admin.indices.stats;
    exports org.elasticsearch.test.action.admin.indices.template.put;
    exports org.elasticsearch.test.action.bulk;
    exports org.elasticsearch.test.action.delete;
    exports org.elasticsearch.test.action.fieldcaps;
    exports org.elasticsearch.test.action.get;
    exports org.elasticsearch.test.action.index;
    exports org.elasticsearch.test.action.ingest;
    exports org.elasticsearch.test.action.main;
    exports org.elasticsearch.test.action.resync;
    exports org.elasticsearch.test.action.search;
    exports org.elasticsearch.test.action.support;
    exports org.elasticsearch.test.action.support.broadcast;
    exports org.elasticsearch.test.action.support.broadcast.node;
    exports org.elasticsearch.test.action.support.master;
    exports org.elasticsearch.test.action.support.nodes;
    exports org.elasticsearch.test.action.support.replication;
    exports org.elasticsearch.test.action.support.single.instance;
    exports org.elasticsearch.test.action.termvectors;
    exports org.elasticsearch.test.action.update;
    exports org.elasticsearch.test.aliases;
    exports org.elasticsearch.test.blocks;
    exports org.elasticsearch.test.bootstrap;
    exports org.elasticsearch.test.broadcast;
    exports org.elasticsearch.test.bwcompat;
    exports org.elasticsearch.test.cli;
    exports org.elasticsearch.test.client;
    exports org.elasticsearch.test.client.documentation;
    exports org.elasticsearch.test.client.node;
    exports org.elasticsearch.test.client.transport;
    exports org.elasticsearch.test.cluster;
    exports org.elasticsearch.test.cluster.ack;
    exports org.elasticsearch.test.cluster.action.shard;
    exports org.elasticsearch.test.cluster.allocation;
    exports org.elasticsearch.test.cluster.block;
    exports org.elasticsearch.test.cluster.health;
    exports org.elasticsearch.test.cluster.metadata;
    exports org.elasticsearch.test.cluster.node;
    exports org.elasticsearch.test.cluster.routing;
    exports org.elasticsearch.test.cluster.routing.allocation;
    exports org.elasticsearch.test.cluster.routing.allocation.decider;
    exports org.elasticsearch.test.cluster.routing.operation.hash.mumur3;
    exports org.elasticsearch.test.cluster.serialization;
    exports org.elasticsearch.test.cluster.service;
    exports org.elasticsearch.test.cluster.settings;
    exports org.elasticsearch.test.cluster.shards;
    exports org.elasticsearch.test.cluster.structure;
    exports org.elasticsearch.test.common;
    exports org.elasticsearch.test.common.blobstore;
    exports org.elasticsearch.test.common.breaker;
    exports org.elasticsearch.test.common.bytes;
    exports org.elasticsearch.test.common.cache;
    exports org.elasticsearch.test.common.collect;
    exports org.elasticsearch.test.common.compress;
    exports org.elasticsearch.test.common.geo;
    exports org.elasticsearch.test.common.geo.builders;
    exports org.elasticsearch.test.common.hash;
    exports org.elasticsearch.test.common.hashing;
    exports org.elasticsearch.test.common.hppc;
    exports org.elasticsearch.test.common.io;
    exports org.elasticsearch.test.common.io.stream;
    exports org.elasticsearch.test.common.joda;
    exports org.elasticsearch.test.common.logging;
    exports org.elasticsearch.test.common.lucene;
    exports org.elasticsearch.test.common.lucene.all;
    exports org.elasticsearch.test.common.lucene.index;
    exports org.elasticsearch.test.common.lucene.search;
    exports org.elasticsearch.test.common.lucene.search.function;
    exports org.elasticsearch.test.common.lucene.search.morelikethis;
    exports org.elasticsearch.test.common.lucene.store;
    exports org.elasticsearch.test.common.lucene.uid;
    exports org.elasticsearch.test.common.network;
    exports org.elasticsearch.test.common.path;
    exports org.elasticsearch.test.common.recycler;
    exports org.elasticsearch.test.common.regex;
    exports org.elasticsearch.test.common.rounding;
    exports org.elasticsearch.test.common.settings;
    exports org.elasticsearch.test.common.transport;
    exports org.elasticsearch.test.common.unit;
    exports org.elasticsearch.test.common.util;
    exports org.elasticsearch.test.common.util.concurrent;
    exports org.elasticsearch.test.common.util.iterable;
    exports org.elasticsearch.test.common.util.set;
    exports org.elasticsearch.test.common.xcontent;
    exports org.elasticsearch.test.common.xcontent.builder;
    exports org.elasticsearch.test.common.xcontent.cbor;
    exports org.elasticsearch.test.common.xcontent.json;
    exports org.elasticsearch.test.common.xcontent.smile;
    exports org.elasticsearch.test.common.xcontent.support;
    exports org.elasticsearch.test.common.xcontent.support.filtering;
    exports org.elasticsearch.test.common.xcontent.yaml;
    exports org.elasticsearch.test.deps.jackson;
    exports org.elasticsearch.test.deps.joda;
    exports org.elasticsearch.test.deps.lucene;
    exports org.elasticsearch.test.discovery;
    exports org.elasticsearch.test.discovery.single;
    exports org.elasticsearch.test.discovery.zen;
    exports org.elasticsearch.test.document;
    exports org.elasticsearch.test.env;
    exports org.elasticsearch.test.explain;
    exports org.elasticsearch.test.gateway;
    exports org.elasticsearch.test.geo;
    exports org.elasticsearch.test.get;
    exports org.elasticsearch.test.hamcrest;
    exports org.elasticsearch.test.index;
    exports org.elasticsearch.test.index.analysis;
    exports org.elasticsearch.test.index.analysis.synonyms;
    exports org.elasticsearch.test.index.cache.bitset;
    exports org.elasticsearch.test.index.codec;
    exports org.elasticsearch.test.index.engine;
    exports org.elasticsearch.test.index.fielddata;
    exports org.elasticsearch.test.index.fielddata.fieldcomparator;
    exports org.elasticsearch.test.index.fielddata.ordinals;
    exports org.elasticsearch.test.index.fielddata.plain;
    exports org.elasticsearch.test.index.fieldstats;
    exports org.elasticsearch.test.index.get;
    exports org.elasticsearch.test.index.mapper;
    exports org.elasticsearch.test.index.query;
    exports org.elasticsearch.test.index.query.functionscore;
    exports org.elasticsearch.test.index.query.plugin;
    exports org.elasticsearch.test.index.refresh;
    exports org.elasticsearch.test.index.reindex;
    exports org.elasticsearch.test.index.replication;
    exports org.elasticsearch.test.index.search;
    exports org.elasticsearch.test.index.search.geo;
    exports org.elasticsearch.test.index.search.nested;
    exports org.elasticsearch.test.index.search.stats;
    exports org.elasticsearch.test.index.seqno;
    exports org.elasticsearch.test.index.shard;
    exports org.elasticsearch.test.index.similarity;
    exports org.elasticsearch.test.index.snapshots.blobstore;
    exports org.elasticsearch.test.index.store;
    exports org.elasticsearch.test.index.suggest.stats;
    exports org.elasticsearch.test.index.termvectors;
    exports org.elasticsearch.test.index.translog;
    exports org.elasticsearch.test.indexing;
    exports org.elasticsearch.test.indexlifecycle;
    exports org.elasticsearch.test.indices;
    exports org.elasticsearch.test.indices.analysis;
    exports org.elasticsearch.test.indices.analyze;
    exports org.elasticsearch.test.indices.cluster;
    exports org.elasticsearch.test.indices.exists.indices;
    exports org.elasticsearch.test.indices.exists.types;
    exports org.elasticsearch.test.indices.flush;
    exports org.elasticsearch.test.indices.mapping;
    exports org.elasticsearch.test.indices.memory.breaker;
    exports org.elasticsearch.test.indices.recovery;
    exports org.elasticsearch.test.indices.settings;
    exports org.elasticsearch.test.indices.state;
    exports org.elasticsearch.test.indices.store;
    exports org.elasticsearch.test.indices.template;
    exports org.elasticsearch.test.ingest;
    exports org.elasticsearch.test.lucene.analysis.miscellaneous;
    exports org.elasticsearch.test.lucene.grouping;
    exports org.elasticsearch.test.lucene.queries;
    exports org.elasticsearch.test.lucene.search;
    exports org.elasticsearch.test.lucene.search.uhighlight;
    exports org.elasticsearch.test.mget;
    exports org.elasticsearch.test.monitor.fs;
    exports org.elasticsearch.test.monitor.jvm;
    exports org.elasticsearch.test.monitor.os;
    exports org.elasticsearch.test.monitor.process;
    exports org.elasticsearch.test.node;
    exports org.elasticsearch.test.node.service;
    exports org.elasticsearch.test.nodesinfo;
    exports org.elasticsearch.test.operateAllIndices;
    exports org.elasticsearch.test.persistent;
    exports org.elasticsearch.test.persistent.decider;
    exports org.elasticsearch.test.plugins;
    exports org.elasticsearch.test.plugins.spi;
    exports org.elasticsearch.test.recovery;
    exports org.elasticsearch.test.repositories;
    exports org.elasticsearch.test.repositories.blobstore;
    exports org.elasticsearch.test.rest;
    exports org.elasticsearch.test.rest.action;
    exports org.elasticsearch.test.rest.action.admin.cluster;
    exports org.elasticsearch.test.rest.action.admin.indices;
    exports org.elasticsearch.test.rest.action.cat;
    exports org.elasticsearch.test.rest.action.document;
    exports org.elasticsearch.test.routing;
    exports org.elasticsearch.test.script;
    exports org.elasticsearch.test.search;
    exports org.elasticsearch.test.search.aggregations;
    exports org.elasticsearch.test.search.aggregations.bucket;
    exports org.elasticsearch.test.search.aggregations.bucket.adjacency;
    exports org.elasticsearch.test.search.aggregations.bucket.composite;
    exports org.elasticsearch.test.search.aggregations.bucket.filter;
    exports org.elasticsearch.test.search.aggregations.bucket.geogrid;
    exports org.elasticsearch.test.search.aggregations.bucket.global;
    exports org.elasticsearch.test.search.aggregations.bucket.histogram;
    exports org.elasticsearch.test.search.aggregations.bucket.missing;
    exports org.elasticsearch.test.search.aggregations.bucket.nested;
    exports org.elasticsearch.test.search.aggregations.bucket.range;
    exports org.elasticsearch.test.search.aggregations.bucket.sampler;
    exports org.elasticsearch.test.search.aggregations.bucket.significant;
    exports org.elasticsearch.test.search.aggregations.bucket.terms;
    exports org.elasticsearch.test.search.aggregations.metrics;
    exports org.elasticsearch.test.search.aggregations.metrics.avg;
    exports org.elasticsearch.test.search.aggregations.metrics.cardinality;
    exports org.elasticsearch.test.search.aggregations.metrics.geobounds;
    exports org.elasticsearch.test.search.aggregations.metrics.geocentroid;
    exports org.elasticsearch.test.search.aggregations.metrics.percentiles;
    exports org.elasticsearch.test.search.aggregations.metrics.percentiles.hdr;
    exports org.elasticsearch.test.search.aggregations.metrics.percentiles.tdigest;
    exports org.elasticsearch.test.search.aggregations.metrics.scripted;
    exports org.elasticsearch.test.search.aggregations.metrics.tophits;
    exports org.elasticsearch.test.search.aggregations.metrics.valuecount;
    exports org.elasticsearch.test.search.aggregations.pipeline;
    exports org.elasticsearch.test.search.aggregations.pipeline.bucketmetrics;
    exports org.elasticsearch.test.search.aggregations.pipeline.bucketmetrics.percentile;
    exports org.elasticsearch.test.search.aggregations.pipeline.bucketmetrics.stats.extended;
    exports org.elasticsearch.test.search.aggregations.pipeline.bucketsort;
    exports org.elasticsearch.test.search.aggregations.pipeline.derivative;
    exports org.elasticsearch.test.search.aggregations.pipeline.moving.avg;
    exports org.elasticsearch.test.search.aggregations.pipeline.serialdiff;
    exports org.elasticsearch.test.search.aggregations.support;
    exports org.elasticsearch.test.search.basic;
    exports org.elasticsearch.test.search.builder;
    exports org.elasticsearch.test.search.child;
    exports org.elasticsearch.test.search.collapse;
    exports org.elasticsearch.test.search.fetch;
    exports org.elasticsearch.test.search.fetch.subphase;
    exports org.elasticsearch.test.search.fetch.subphase.highlight;
    exports org.elasticsearch.test.search.fields;
    exports org.elasticsearch.test.search.functionscore;
    exports org.elasticsearch.test.search.geo;
    exports org.elasticsearch.test.search.internal;
    exports org.elasticsearch.test.search.morelikethis;
    exports org.elasticsearch.test.search.msearch;
    exports org.elasticsearch.test.search.nested;
    exports org.elasticsearch.test.search.preference;
    exports org.elasticsearch.test.search.profile;
    exports org.elasticsearch.test.search.profile.aggregation;
    exports org.elasticsearch.test.search.profile.query;
    exports org.elasticsearch.test.search.query;
    exports org.elasticsearch.test.search.rescore;
    exports org.elasticsearch.test.search.scriptfilter;
    exports org.elasticsearch.test.search.scroll;
    exports org.elasticsearch.test.search.searchafter;
    exports org.elasticsearch.test.search.simple;
    exports org.elasticsearch.test.search.slice;
    exports org.elasticsearch.test.search.sort;
    exports org.elasticsearch.test.search.source;
    exports org.elasticsearch.test.search.stats;
    exports org.elasticsearch.test.search.suggest;
    exports org.elasticsearch.test.search.suggest.completion;
    exports org.elasticsearch.test.search.suggest.phrase;
    exports org.elasticsearch.test.search.suggest.term;
    exports org.elasticsearch.test.similarity;
    exports org.elasticsearch.test.snapshots;
    exports org.elasticsearch.test.snapshots.mockstore;
    exports org.elasticsearch.test.tasks;
    exports org.elasticsearch.test.threadpool;
    exports org.elasticsearch.test.transport;
    exports org.elasticsearch.test.update;
    exports org.elasticsearch.test.usage;
    exports org.elasticsearch.test.validate;
    exports org.elasticsearch.test.versioning;
    exports org.elasticsearch.test.watcher;

    opens org.elasticsearch.test;
    opens org.elasticsearch.test.action.admin;
    opens org.elasticsearch.test.action.bulk;
    opens org.elasticsearch.test.action.fieldstats;
    opens org.elasticsearch.test.action.search;
    opens org.elasticsearch.test.action.termvectors;
    opens org.elasticsearch.test.cluster.routing;
    opens org.elasticsearch.test.common.settings.loader;
    opens org.elasticsearch.test.config;
    opens org.elasticsearch.test.config.garbage;
    opens org.elasticsearch.test.gateway;
    opens org.elasticsearch.test.index.analysis;
    opens org.elasticsearch.test.index.analysis.synonyms;
    opens org.elasticsearch.test.index.mapper;
    opens org.elasticsearch.test.index.mapper.dynamictemplate.genericstore;
    opens org.elasticsearch.test.index.mapper.dynamictemplate.pathmatch;
    opens org.elasticsearch.test.index.mapper.dynamictemplate.simple;
    opens org.elasticsearch.test.index.mapper.multifield;
    opens org.elasticsearch.test.index.mapper.multifield.merge;
    opens org.elasticsearch.test.index.mapper.path;
    opens org.elasticsearch.test.index.mapper.simple;
    opens org.elasticsearch.test.index.query;
    opens org.elasticsearch.test.index.translog;
    opens org.elasticsearch.test.indices.analyze.conf_dir.hunspell.en_US;
    opens org.elasticsearch.test.indices.analyze.conf_dir.hunspell.en_US_custom;
    opens org.elasticsearch.test.indices.analyze.no_aff_conf_dir.hunspell.en_US;
    opens org.elasticsearch.test.indices.analyze.two_aff_conf_dir.hunspell.en_US;
    opens org.elasticsearch.test.indices.bwc;
    opens org.elasticsearch.test.plugins;
    opens org.elasticsearch.test.search.geo;
    opens org.elasticsearch.test.search.query;

    uses org.elasticsearch.plugins.spi.NamedXContentProvider;

    provides org.elasticsearch.plugins.spi.NamedXContentProvider
            with org.elasticsearch.test.plugins.spi.DummyNamedXContentProvider;

    requires jdk.management;
    requires junit;
    requires hamcrest.all;
    requires jimfs;
    requires commons.codec;
    requires org.xbib.elasticsearch.testframework;
    requires org.xbib.elasticsearch.server;
    requires org.xbib.elasticsearch.lucene;
    requires org.xbib.elasticsearch.lucene.testframework;
    requires org.xbib.elasticsearch.randomizedtesting;
    requires org.xbib.elasticsearch.hdrhistogram;
    requires org.xbib.elasticsearch.hppc;
    requires org.xbib.elasticsearch.log4j;
    requires org.xbib.elasticsearch.jackson;
    requires org.xbib.elasticsearch.joda;
    requires org.xbib.elasticsearch.joptsimple;
    requires org.xbib.elasticsearch.jts;
    requires org.xbib.elasticsearch.mocksocket;
    requires org.xbib.elasticsearch.spatial4j;
    requires org.xbib.elasticsearch.securemock;
}
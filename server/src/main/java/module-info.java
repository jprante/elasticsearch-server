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
    exports org.elasticsearch.action;
    exports org.elasticsearch.action.admin.cluster.allocation;
    exports org.elasticsearch.action.admin.cluster.health;
    exports org.elasticsearch.action.admin.cluster.node.hotthreads;
    exports org.elasticsearch.action.admin.cluster.node.info;
    exports org.elasticsearch.action.admin.cluster.node.liveness;
    exports org.elasticsearch.action.admin.cluster.node.stats;
    exports org.elasticsearch.action.admin.cluster.node.tasks.cancel;
    exports org.elasticsearch.action.admin.cluster.node.tasks.get;
    exports org.elasticsearch.action.admin.cluster.node.tasks.list;
    exports org.elasticsearch.action.admin.cluster.node.usage;
    exports org.elasticsearch.action.admin.cluster.remote;
    exports org.elasticsearch.action.admin.cluster.repositories.delete;
    exports org.elasticsearch.action.admin.cluster.repositories.get;
    exports org.elasticsearch.action.admin.cluster.repositories.put;
    exports org.elasticsearch.action.admin.cluster.repositories.verify;
    exports org.elasticsearch.action.admin.cluster.reroute;
    exports org.elasticsearch.action.admin.cluster.settings;
    exports org.elasticsearch.action.admin.cluster.shards;
    exports org.elasticsearch.action.admin.cluster.snapshots.create;
    exports org.elasticsearch.action.admin.cluster.snapshots.get;
    exports org.elasticsearch.action.admin.cluster.snapshots.delete;
    exports org.elasticsearch.action.admin.cluster.snapshots.restore;
    exports org.elasticsearch.action.admin.cluster.snapshots.status;
    exports org.elasticsearch.action.admin.cluster.state;
    exports org.elasticsearch.action.admin.cluster.stats;
    exports org.elasticsearch.action.admin.cluster.storedscripts;
    exports org.elasticsearch.action.admin.cluster.tasks;
    exports org.elasticsearch.action.admin.indices.alias;
    exports org.elasticsearch.action.admin.indices.alias.exists;
    exports org.elasticsearch.action.admin.indices.alias.get;
    exports org.elasticsearch.action.admin.indices.analyze;
    exports org.elasticsearch.action.admin.indices.cache.clear;
    exports org.elasticsearch.action.admin.indices.close;
    exports org.elasticsearch.action.admin.indices.create;
    exports org.elasticsearch.action.admin.indices.delete;
    exports org.elasticsearch.action.admin.indices.exists.indices;
    exports org.elasticsearch.action.admin.indices.exists.types;
    exports org.elasticsearch.action.admin.indices.flush;
    exports org.elasticsearch.action.admin.indices.forcemerge;
    exports org.elasticsearch.action.admin.indices.get;
    exports org.elasticsearch.action.admin.indices.mapping.get;
    exports org.elasticsearch.action.admin.indices.mapping.put;
    exports org.elasticsearch.action.admin.indices.open;
    exports org.elasticsearch.action.admin.indices.recovery;
    exports org.elasticsearch.action.admin.indices.refresh;
    exports org.elasticsearch.action.admin.indices.rollover;
    exports org.elasticsearch.action.admin.indices.segments;
    exports org.elasticsearch.action.admin.indices.settings.get;
    exports org.elasticsearch.action.admin.indices.settings.put;
    exports org.elasticsearch.action.admin.indices.shards;
    exports org.elasticsearch.action.admin.indices.stats;
    exports org.elasticsearch.action.admin.indices.shrink;
    exports org.elasticsearch.action.admin.indices.template.delete;
    exports org.elasticsearch.action.admin.indices.template.get;
    exports org.elasticsearch.action.admin.indices.template.put;
    exports org.elasticsearch.action.admin.indices.upgrade.get;
    exports org.elasticsearch.action.admin.indices.upgrade.post;
    exports org.elasticsearch.action.admin.indices.validate.query;
    exports org.elasticsearch.action.bulk;
    exports org.elasticsearch.action.delete;
    exports org.elasticsearch.action.explain;
    exports org.elasticsearch.action.fieldcaps;
    exports org.elasticsearch.action.get;
    exports org.elasticsearch.action.index;
    exports org.elasticsearch.action.ingest;
    exports org.elasticsearch.action.main;
    exports org.elasticsearch.action.resync;
    exports org.elasticsearch.action.search;
    exports org.elasticsearch.action.termvectors;
    exports org.elasticsearch.action.update;
    exports org.elasticsearch.action.support;
    exports org.elasticsearch.action.support.broadcast;
    exports org.elasticsearch.action.support.broadcast.node;
    exports org.elasticsearch.action.support.master;
    exports org.elasticsearch.action.support.nodes;
    exports org.elasticsearch.action.support.replication;
    exports org.elasticsearch.action.support.single.instance;
    exports org.elasticsearch.action.support.single.shard;
    exports org.elasticsearch.action.support.tasks;
    exports org.elasticsearch.bootstrap;
    exports org.elasticsearch.cli;
    exports org.elasticsearch.client;
    exports org.elasticsearch.client.node;
    exports org.elasticsearch.client.support;
    exports org.elasticsearch.client.transport;
    exports org.elasticsearch.cluster;
    exports org.elasticsearch.cluster.ack;
    exports org.elasticsearch.cluster.action.index;
    exports org.elasticsearch.cluster.action.shard;
    exports org.elasticsearch.cluster.block;
    exports org.elasticsearch.cluster.health;
    exports org.elasticsearch.cluster.metadata;
    exports org.elasticsearch.cluster.node;
    exports org.elasticsearch.cluster.routing;
    exports org.elasticsearch.cluster.routing.allocation;
    exports org.elasticsearch.cluster.routing.allocation.allocator;
    exports org.elasticsearch.cluster.routing.allocation.command;
    exports org.elasticsearch.cluster.routing.allocation.decider;
    exports org.elasticsearch.cluster.service;
    exports org.elasticsearch.common;
    exports org.elasticsearch.common.blobstore;
    exports org.elasticsearch.common.blobstore.fs;
    exports org.elasticsearch.common.blobstore.support;
    exports org.elasticsearch.common.breaker;
    exports org.elasticsearch.common.bytes;
    exports org.elasticsearch.common.cache;
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
    exports org.elasticsearch.common.xcontent.support.filtering;
    exports org.elasticsearch.discovery;
    exports org.elasticsearch.discovery.single;
    exports org.elasticsearch.discovery.zen;
    exports org.elasticsearch.env;
    exports org.elasticsearch.gateway;
    exports org.elasticsearch.http;
    exports org.elasticsearch.index;
    exports org.elasticsearch.index.analysis;
    exports org.elasticsearch.index.engine;
    exports org.elasticsearch.index.cache;
    exports org.elasticsearch.index.cache.bitset;
    exports org.elasticsearch.index.cache.query;
    exports org.elasticsearch.index.cache.request;
    exports org.elasticsearch.index.codec;
    exports org.elasticsearch.index.fielddata;
    exports org.elasticsearch.index.fielddata.fieldcomparator;
    exports org.elasticsearch.index.fielddata.ordinals;
    exports org.elasticsearch.index.fielddata.plain;
    exports org.elasticsearch.index.fieldvisitor;
    exports org.elasticsearch.index.flush;
    exports org.elasticsearch.index.get;
    exports org.elasticsearch.index.mapper;
    exports org.elasticsearch.index.merge;
    exports org.elasticsearch.index.query;
    exports org.elasticsearch.index.query.functionscore;
    exports org.elasticsearch.index.query.support;
    exports org.elasticsearch.index.recovery;
    exports org.elasticsearch.index.refresh;
    exports org.elasticsearch.index.reindex;
    exports org.elasticsearch.index.seqno;
    exports org.elasticsearch.index.search;
    exports org.elasticsearch.index.search.stats;
    exports org.elasticsearch.index.settings;
    exports org.elasticsearch.index.shard;
    exports org.elasticsearch.index.similarity;
    exports org.elasticsearch.index.snapshots;
    exports org.elasticsearch.index.snapshots.blobstore;
    exports org.elasticsearch.index.store;
    exports org.elasticsearch.index.termvectors;
    exports org.elasticsearch.index.translog;
    exports org.elasticsearch.index.warmer;
    exports org.elasticsearch.indices;
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
    exports org.elasticsearch.rest.action;
    exports org.elasticsearch.rest.action.admin.indices;
    exports org.elasticsearch.rest.action.admin.cluster;
    exports org.elasticsearch.rest.action.cat;
    exports org.elasticsearch.rest.action.document;
    exports org.elasticsearch.rest.action.ingest;
    exports org.elasticsearch.rest.action.search;
    exports org.elasticsearch.script;
    exports org.elasticsearch.search;
    exports org.elasticsearch.search.aggregations;
    exports org.elasticsearch.search.aggregations.bucket;
    exports org.elasticsearch.search.aggregations.bucket.adjacency;
    exports org.elasticsearch.search.aggregations.bucket.composite;
    exports org.elasticsearch.search.aggregations.bucket.filter;
    exports org.elasticsearch.search.aggregations.bucket.geogrid;
    exports org.elasticsearch.search.aggregations.bucket.global;
    exports org.elasticsearch.search.aggregations.bucket.histogram;
    exports org.elasticsearch.search.aggregations.bucket.missing;
    exports org.elasticsearch.search.aggregations.bucket.nested;
    exports org.elasticsearch.search.aggregations.bucket.range;
    exports org.elasticsearch.search.aggregations.bucket.sampler;
    exports org.elasticsearch.search.aggregations.bucket.significant;
    exports org.elasticsearch.search.aggregations.bucket.significant.heuristics;
    exports org.elasticsearch.search.aggregations.bucket.terms;
    exports org.elasticsearch.search.aggregations.metrics;
    exports org.elasticsearch.search.aggregations.metrics.avg;
    exports org.elasticsearch.search.aggregations.metrics.cardinality;
    exports org.elasticsearch.search.aggregations.metrics.geobounds;
    exports org.elasticsearch.search.aggregations.metrics.geocentroid;
    exports org.elasticsearch.search.aggregations.metrics.max;
    exports org.elasticsearch.search.aggregations.metrics.min;
    exports org.elasticsearch.search.aggregations.metrics.percentiles;
    exports org.elasticsearch.search.aggregations.metrics.percentiles.hdr;
    exports org.elasticsearch.search.aggregations.metrics.percentiles.tdigest;
    exports org.elasticsearch.search.aggregations.metrics.scripted;
    exports org.elasticsearch.search.aggregations.metrics.stats;
    exports org.elasticsearch.search.aggregations.metrics.stats.extended;
    exports org.elasticsearch.search.aggregations.metrics.sum;
    exports org.elasticsearch.search.aggregations.metrics.tophits;
    exports org.elasticsearch.search.aggregations.metrics.valuecount;
    exports org.elasticsearch.search.aggregations.pipeline;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics.avg;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics.max;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics.min;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics.percentile;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics.stats;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics.stats.extended;
    exports org.elasticsearch.search.aggregations.pipeline.bucketmetrics.sum;
    exports org.elasticsearch.search.aggregations.pipeline.bucketscript;
    exports org.elasticsearch.search.aggregations.pipeline.bucketselector;
    exports org.elasticsearch.search.aggregations.pipeline.bucketsort;
    exports org.elasticsearch.search.aggregations.pipeline.cumulativesum;
    exports org.elasticsearch.search.aggregations.pipeline.derivative;
    exports org.elasticsearch.search.aggregations.pipeline.movavg;
    exports org.elasticsearch.search.aggregations.pipeline.movavg.models;
    exports org.elasticsearch.search.aggregations.pipeline.serialdiff;
    exports org.elasticsearch.search.aggregations.support;
    exports org.elasticsearch.search.aggregations.support.values;
    exports org.elasticsearch.search.builder;
    exports org.elasticsearch.search.collapse;
    exports org.elasticsearch.search.dfs;
    exports org.elasticsearch.search.fetch;
    exports org.elasticsearch.search.fetch.subphase;
    exports org.elasticsearch.search.fetch.subphase.highlight;
    exports org.elasticsearch.search.lookup;
    exports org.elasticsearch.search.query;
    exports org.elasticsearch.search.profile;
    exports org.elasticsearch.search.profile.aggregation;
    exports org.elasticsearch.search.profile.query;
    exports org.elasticsearch.search.rescore;
    exports org.elasticsearch.search.searchafter;
    exports org.elasticsearch.search.slice;
    exports org.elasticsearch.search.sort;
    exports org.elasticsearch.search.suggest;
    exports org.elasticsearch.search.suggest.completion.context;
    exports org.elasticsearch.search.suggest.completion;
    exports org.elasticsearch.search.suggest.phrase;
    exports org.elasticsearch.search.suggest.term;
    exports org.elasticsearch.snapshots;
    exports org.elasticsearch.tasks;
    exports org.elasticsearch.threadpool;
    exports org.elasticsearch.transport;
    exports org.elasticsearch.usage;
    exports org.elasticsearch.watcher;

    requires org.xbib.elasticsearch.jna;
    requires org.xbib.elasticsearch.log4j;
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
    requires jdk.management;

    uses org.elasticsearch.common.xcontent.XContentBuilderExtension;

    provides org.elasticsearch.common.xcontent.XContentBuilderExtension
            with XContentElasticsearchExtension;

}

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
module org.xbib.elasticsearch.lucene {

    exports org.apache.lucene;
    exports org.apache.lucene.analysis;
    exports org.apache.lucene.analysis.ar;
    exports org.apache.lucene.analysis.bg;
    exports org.apache.lucene.analysis.bn;
    exports org.apache.lucene.analysis.br;
    exports org.apache.lucene.analysis.ca;
    exports org.apache.lucene.analysis.charfilter;
    exports org.apache.lucene.analysis.cjk;
    exports org.apache.lucene.analysis.ckb;
    exports org.apache.lucene.analysis.commongrams;
    exports org.apache.lucene.analysis.compound;
    exports org.apache.lucene.analysis.core;
    exports org.apache.lucene.analysis.custom;
    exports org.apache.lucene.analysis.cz;
    exports org.apache.lucene.analysis.da;
    exports org.apache.lucene.analysis.de;
    exports org.apache.lucene.analysis.el;
    exports org.apache.lucene.analysis.en;
    exports org.apache.lucene.analysis.es;
    exports org.apache.lucene.analysis.eu;
    exports org.apache.lucene.analysis.fa;
    exports org.apache.lucene.analysis.fi;
    exports org.apache.lucene.analysis.fr;
    exports org.apache.lucene.analysis.ga;
    exports org.apache.lucene.analysis.gl;
    exports org.apache.lucene.analysis.hi;
    exports org.apache.lucene.analysis.hu;
    exports org.apache.lucene.analysis.hunspell;
    exports org.apache.lucene.analysis.hy;
    exports org.apache.lucene.analysis.id;
    exports org.apache.lucene.analysis.in;
    exports org.apache.lucene.analysis.it;
    exports org.apache.lucene.analysis.lt;
    exports org.apache.lucene.analysis.lv;
    exports org.apache.lucene.analysis.minhash;
    exports org.apache.lucene.analysis.miscellaneous;
    exports org.apache.lucene.analysis.ngram;
    exports org.apache.lucene.analysis.nl;
    exports org.apache.lucene.analysis.no;
    exports org.apache.lucene.analysis.path;
    exports org.apache.lucene.analysis.pattern;
    exports org.apache.lucene.analysis.payloads;
    exports org.apache.lucene.analysis.pt;
    exports org.apache.lucene.analysis.query;
    exports org.apache.lucene.analysis.reverse;
    exports org.apache.lucene.analysis.ro;
    exports org.apache.lucene.analysis.ru;
    exports org.apache.lucene.analysis.shingle;
    exports org.apache.lucene.analysis.sinks;
    exports org.apache.lucene.analysis.snowball;
    exports org.apache.lucene.analysis.sr;
    exports org.apache.lucene.analysis.standard;
    exports org.apache.lucene.analysis.sv;
    exports org.apache.lucene.analysis.synonym;
    exports org.apache.lucene.analysis.th;
    exports org.apache.lucene.analysis.tokenattributes;
    exports org.apache.lucene.analysis.tr;
    exports org.apache.lucene.analysis.util;
    exports org.apache.lucene.analysis.wikipedia;
    exports org.apache.lucene.codecs;
    exports org.apache.lucene.codecs.blocktree;
    exports org.apache.lucene.codecs.lucene50;
    exports org.apache.lucene.codecs.lucene70;
    exports org.apache.lucene.collation;
    exports org.apache.lucene.document;
    exports org.apache.lucene.geo;
    exports org.apache.lucene.index;
    exports org.apache.lucene.index.memory;
    exports org.apache.lucene.misc;
    exports org.apache.lucene.payloads;
    exports org.apache.lucene.queries;
    exports org.apache.lucene.queryparser.classic;
    exports org.apache.lucene.queryparser.complexPhrase;
    exports org.apache.lucene.queryparser.ext;
    exports org.apache.lucene.queryparser.simple;
    exports org.apache.lucene.queryparser.xml;
    exports org.apache.lucene.sandbox.queries;
    exports org.apache.lucene.search;
    exports org.apache.lucene.search.grouping;
    exports org.apache.lucene.search.highlight;
    exports org.apache.lucene.search.join;
    exports org.apache.lucene.search.similarities;
    exports org.apache.lucene.search.spans;
    exports org.apache.lucene.search.spell;
    exports org.apache.lucene.search.suggest;
    exports org.apache.lucene.search.suggest.analyzing;
    exports org.apache.lucene.search.suggest.document;
    exports org.apache.lucene.search.uhighlight;
    exports org.apache.lucene.search.vectorhighlight;
    exports org.apache.lucene.spatial.bbox;
    exports org.apache.lucene.spatial.composite;
    exports org.apache.lucene.spatial.prefix;
    exports org.apache.lucene.spatial.prefix.tree;
    exports org.apache.lucene.spatial.query;
    exports org.apache.lucene.spatial.serialized;
    exports org.apache.lucene.spatial.spatial4j;
    exports org.apache.lucene.spatial.util;
    exports org.apache.lucene.spatial.vector;
    exports org.apache.lucene.spatial3d;
    exports org.apache.lucene.spatial3d.geom;
    exports org.apache.lucene.store;
    exports org.apache.lucene.util;
    exports org.apache.lucene.util.automaton;
    exports org.apache.lucene.util.bkd;
    exports org.apache.lucene.util.fst;
    exports org.apache.lucene.util.graph;
    exports org.apache.lucene.util.mutable;
    exports org.apache.lucene.util.packed;
    exports org.tartarus.snowball;
    exports org.tartarus.snowball.ext;

    provides org.apache.lucene.codecs.Codec with
            org.apache.lucene.codecs.lucene70.Lucene70Codec;

    provides org.apache.lucene.codecs.DocValuesFormat with
            org.apache.lucene.codecs.lucene70.Lucene70DocValuesFormat;

    provides org.apache.lucene.codecs.PostingsFormat with
            org.apache.lucene.codecs.lucene50.Lucene50PostingsFormat,
            org.apache.lucene.search.suggest.document.Completion50PostingsFormat,
            org.apache.lucene.codecs.idversion.IDVersionPostingsFormat;

    requires java.logging;

    requires transitive java.desktop;
    requires transitive java.xml;

    requires org.xbib.elasticsearch.spatial4j;
    requires org.xbib.elasticsearch.s2geo;
}

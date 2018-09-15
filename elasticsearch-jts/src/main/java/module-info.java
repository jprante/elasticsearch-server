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
module org.xbib.elasticsearch.jts {
    exports org.locationtech.jts;
    exports org.locationtech.jts.algorithm;
    exports org.locationtech.jts.algorithm.distance;
    exports org.locationtech.jts.algorithm.locate;
    exports org.locationtech.jts.algorithm.match;
    //exports org.locationtech.jts.awt;
    exports org.locationtech.jts.densify;
    exports org.locationtech.jts.dissolve;
    exports org.locationtech.jts.edgegraph;
    exports org.locationtech.jts.geom;
    exports org.locationtech.jts.geom.impl;
    exports org.locationtech.jts.geom.prep;
    exports org.locationtech.jts.geom.util;
    exports org.locationtech.jts.geomgraph;
    exports org.locationtech.jts.geomgraph.index;
    exports org.locationtech.jts.index;
    exports org.locationtech.jts.index.bintree;
    exports org.locationtech.jts.index.chain;
    exports org.locationtech.jts.index.intervalrtree;
    exports org.locationtech.jts.index.kdtree;
    exports org.locationtech.jts.index.quadtree;
    exports org.locationtech.jts.index.strtree;
    exports org.locationtech.jts.index.sweepline;
    exports org.locationtech.jts.io;
    //exports org.locationtech.jts.io.gml2;
    exports org.locationtech.jts.io.kml;
    exports org.locationtech.jts.linearref;
    exports org.locationtech.jts.math;
    exports org.locationtech.jts.noding;
    exports org.locationtech.jts.noding.snapround;
    exports org.locationtech.jts.operation;
    exports org.locationtech.jts.operation.buffer;
    exports org.locationtech.jts.operation.distance;
    exports org.locationtech.jts.operation.distance3d;
    exports org.locationtech.jts.operation.linemerge;
    exports org.locationtech.jts.operation.overlay;
    exports org.locationtech.jts.operation.polygonize;
    exports org.locationtech.jts.operation.predicate;
    exports org.locationtech.jts.operation.relate;
    exports org.locationtech.jts.operation.union;
    exports org.locationtech.jts.operation.valid;
    exports org.locationtech.jts.planargraph;
    exports org.locationtech.jts.precision;
    exports org.locationtech.jts.shape;
    exports org.locationtech.jts.shape.fractal;
    exports org.locationtech.jts.shape.random;
    exports org.locationtech.jts.simplify;
    exports org.locationtech.jts.triangulate;
    exports org.locationtech.jts.triangulate.quadedge;
    exports org.locationtech.jts.util;

    //requires java.desktop; // we removed awt and io.gml2 XML stuff
}
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
module org.xbib.elasticsearch.spatial4j {
    exports org.locationtech.spatial4j;
    exports org.locationtech.spatial4j.context;
    exports org.locationtech.spatial4j.context.jts;
    exports org.locationtech.spatial4j.distance;
    exports org.locationtech.spatial4j.exception;
    exports org.locationtech.spatial4j.io;
    exports org.locationtech.spatial4j.io.jackson;
    exports org.locationtech.spatial4j.io.jts;
    exports org.locationtech.spatial4j.shape;
    exports org.locationtech.spatial4j.shape.impl;
    exports org.locationtech.spatial4j.shape.jts;

    requires org.xbib.elasticsearch.jts;
    requires org.xbib.elasticsearch.noggit;
    requires org.xbib.elasticsearch.jackson;

}

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
package org.elasticsearch.test.index.mapper;

import org.apache.lucene.util.BytesRef;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.compress.CompressedXContent;
import org.elasticsearch.common.geo.GeoPoint;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.mapper.DocumentMapper;
import org.elasticsearch.index.mapper.DocumentMapperParser;
import org.elasticsearch.index.mapper.FieldMapper;
import org.elasticsearch.index.mapper.GeoPointFieldMapper;
import org.elasticsearch.index.mapper.MapperParsingException;
import org.elasticsearch.index.mapper.ParsedDocument;
import org.elasticsearch.index.mapper.SourceToParse;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.testframework.ESSingleNodeTestCase;
import org.elasticsearch.testframework.InternalSettingsPlugin;
import org.elasticsearch.test.geo.RandomGeoGenerator;
import org.hamcrest.CoreMatchers;

import java.io.IOException;
import java.util.Collection;

import static org.elasticsearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.elasticsearch.common.geo.GeoHashUtils.stringEncode;
import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.elasticsearch.index.mapper.GeoPointFieldMapper.Names.IGNORE_Z_VALUE;
import static org.elasticsearch.index.mapper.GeoPointFieldMapper.Names.NULL_VALUE;
import static org.elasticsearch.index.query.QueryBuilders.matchAllQuery;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

public class GeoPointFieldMapperTests extends ESSingleNodeTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> getPlugins() {
        return pluginList(InternalSettingsPlugin.class);
    }

    public void testGeoHashValue() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type", new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .field("point", stringEncode(1.3, 1.2))
                        .endObject()),
                XContentType.JSON));

        assertThat(doc.rootDoc().getField("point"), notNullValue());
    }

    public void testLatLonValuesStored() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.field("store", true).endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type", new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .startObject("point").field("lat", 1.2).field("lon", 1.3).endObject()
                        .endObject()),
                XContentType.JSON));

        assertThat(doc.rootDoc().getField("point"), notNullValue());
    }

    public void testArrayLatLonValues() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point").field("doc_values", false);
        String mapping = Strings.toString(xContentBuilder.field("store", true).endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type", new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .startArray("point")
                        .startObject().field("lat", 1.2).field("lon", 1.3).endObject()
                        .startObject().field("lat", 1.4).field("lon", 1.5).endObject()
                        .endArray()
                        .endObject()),
                XContentType.JSON));

        // doc values are enabled by default, but in this test we disable them; we should only have 2 points
        assertThat(doc.rootDoc().getFields("point"), notNullValue());
        assertThat(doc.rootDoc().getFields("point").length, equalTo(4));
    }

    public void testLatLonInOneValue() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type",
            new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .field("point", "1.2,1.3")
                        .endObject()),
                XContentType.JSON));

        assertThat(doc.rootDoc().getField("point"), notNullValue());
    }

    public void testLatLonStringWithZValue() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point")
            .field(IGNORE_Z_VALUE.getPreferredName(), true);
        String mapping = Strings.toString(xContentBuilder.endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type",
            new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
            .bytes(XContentFactory.jsonBuilder()
                .startObject()
                .field("point", "1.2,1.3,10.0")
                .endObject()),
            XContentType.JSON));

        assertThat(doc.rootDoc().getField("point"), notNullValue());
    }

    public void testLatLonStringWithZValueException() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point")
            .field(IGNORE_Z_VALUE.getPreferredName(), false);
        String mapping = Strings.toString(xContentBuilder.endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type",
            new CompressedXContent(mapping));

        SourceToParse source = SourceToParse.source("test", "type", "1", BytesReference
            .bytes(XContentFactory.jsonBuilder()
                .startObject()
                .field("point", "1.2,1.3,10.0")
                .endObject()),
            XContentType.JSON);

        Exception e = expectThrows(MapperParsingException.class, () -> defaultMapper.parse(source));
        assertThat(e.getCause().getMessage(), containsString("but [ignore_z_value] parameter is [false]"));
    }

    public void testLatLonInOneValueStored() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.field("store", true).endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type",
            new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .field("point", "1.2,1.3")
                        .endObject()),
                XContentType.JSON));
        assertThat(doc.rootDoc().getField("point"), notNullValue());
    }

    public void testLatLonInOneValueArray() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point").field("doc_values", false);
        String mapping = Strings.toString(xContentBuilder.field("store", true).endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type",
            new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .startArray("point")
                        .value("1.2,1.3")
                        .value("1.4,1.5")
                        .endArray()
                        .endObject()),
                XContentType.JSON));

        // doc values are enabled by default, but in this test we disable them; we should only have 2 points
        assertThat(doc.rootDoc().getFields("point"), notNullValue());
        assertThat(doc.rootDoc().getFields("point").length, equalTo(4));
    }

    public void testLonLatArray() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type", new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .startArray("point").value(1.3).value(1.2).endArray()
                        .endObject()),
                XContentType.JSON));

        assertThat(doc.rootDoc().getField("point"), notNullValue());
    }

    public void testLonLatArrayDynamic() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startArray("dynamic_templates").startObject().startObject("point").field("match", "point*")
            .startObject("mapping").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.endObject().endObject().endObject().endArray().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type", new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .startArray("point").value(1.3).value(1.2).endArray()
                        .endObject()),
                XContentType.JSON));

        assertThat(doc.rootDoc().getField("point"), notNullValue());
    }

    public void testLonLatArrayStored() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.field("store", true).endObject().endObject().endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type", new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .startArray("point").value(1.3).value(1.2).endArray()
                        .endObject()),
                XContentType.JSON));

        assertThat(doc.rootDoc().getField("point"), notNullValue());
        assertThat(doc.rootDoc().getFields("point").length, equalTo(3));
    }

    public void testLonLatArrayArrayStored() throws Exception {
        XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("point").field("type", "geo_point");
        String mapping = Strings.toString(xContentBuilder.field("store", true).field("doc_values", false).endObject().endObject()
            .endObject().endObject());
        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser().parse("type", new CompressedXContent(mapping));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                        .startObject()
                        .startArray("point")
                        .startArray().value(1.3).value(1.2).endArray()
                        .startArray().value(1.5).value(1.4).endArray()
                        .endArray()
                        .endObject()),
                XContentType.JSON));

        assertThat(doc.rootDoc().getFields("point"), notNullValue());
        assertThat(doc.rootDoc().getFields("point").length, CoreMatchers.equalTo(4));
    }

    /**
     * Test that accept_z_value parameter correctly parses
     */
    public void testIgnoreZValue() throws IOException {
        String mapping = Strings.toString(XContentFactory.jsonBuilder().startObject().startObject("type1")
            .startObject("properties").startObject("location")
            .field("type", "geo_point")
            .field(IGNORE_Z_VALUE.getPreferredName(), "true")
            .endObject().endObject()
            .endObject().endObject());

        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser()
            .parse("type1", new CompressedXContent(mapping));
        FieldMapper fieldMapper = defaultMapper.mappers().getMapper("location");
        assertThat(fieldMapper, instanceOf(GeoPointFieldMapper.class));

        boolean ignoreZValue = ((GeoPointFieldMapper)fieldMapper).ignoreZValue().value();
        assertThat(ignoreZValue, equalTo(true));

        // explicit false accept_z_value test
        mapping = Strings.toString(XContentFactory.jsonBuilder().startObject().startObject("type1")
            .startObject("properties").startObject("location")
            .field("type", "geo_point")
            .field(IGNORE_Z_VALUE.getPreferredName(), "false")
            .endObject().endObject()
            .endObject().endObject());

        defaultMapper = createIndex("test2").mapperService().documentMapperParser().parse("type1", new CompressedXContent(mapping));
        fieldMapper = defaultMapper.mappers().getMapper("location");
        assertThat(fieldMapper, instanceOf(GeoPointFieldMapper.class));

        ignoreZValue = ((GeoPointFieldMapper)fieldMapper).ignoreZValue().value();
        assertThat(ignoreZValue, equalTo(false));
    }

    public void testMultiField() throws Exception {
        int numDocs = randomIntBetween(10, 100);
        String mapping = Strings.toString(XContentFactory.jsonBuilder().startObject().startObject("pin").startObject("properties").startObject("location")
            .field("type", "geo_point")
            .startObject("fields")
            .startObject("geohash").field("type", "keyword").endObject()  // test geohash as keyword
            .startObject("latlon").field("type", "keyword").endObject()  // test geohash as string
            .endObject()
            .endObject().endObject().endObject().endObject());
        CreateIndexRequestBuilder mappingRequest = client().admin().indices().prepareCreate("test")
            .addMapping("pin", mapping, XContentType.JSON);
        mappingRequest.execute().actionGet();

        // create index and add random test points
        client().admin().cluster().prepareHealth().setWaitForEvents(Priority.LANGUID).setWaitForGreenStatus().execute().actionGet();
        for (int i=0; i<numDocs; ++i) {
            final GeoPoint pt = RandomGeoGenerator.randomPoint(random());
            client().prepareIndex("test", "pin").setSource(jsonBuilder().startObject().startObject("location").field("lat", pt.lat())
                .field("lon", pt.lon()).endObject().endObject()).setRefreshPolicy(IMMEDIATE).get();
        }

        // TODO these tests are bogus and need to be Fix
        // query by geohash subfield
        SearchResponse searchResponse = client().prepareSearch().addStoredField("location.geohash").setQuery(matchAllQuery()).execute().actionGet();
        assertEquals(numDocs, searchResponse.getHits().getTotalHits());

        // query by latlon subfield
        searchResponse = client().prepareSearch().addStoredField("location.latlon").setQuery(matchAllQuery()).execute().actionGet();
        assertEquals(numDocs, searchResponse.getHits().getTotalHits());
    }


    public void testEmptyName() throws Exception {
        // after 5.x
        String mapping = Strings.toString(XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("").field("type", "geo_point").endObject().endObject()
            .endObject().endObject());

        DocumentMapperParser parser = createIndex("test").mapperService().documentMapperParser();
        IllegalArgumentException e = expectThrows(IllegalArgumentException.class,
            () -> parser.parse("type", new CompressedXContent(mapping))
        );
        assertThat(e.getMessage(), containsString("name cannot be empty string"));
    }

    public void testNullValue() throws Exception {
        String mapping = Strings.toString(XContentFactory.jsonBuilder().startObject().startObject("type")
            .startObject("properties").startObject("location")
            .field("type", "geo_point")
            .field(NULL_VALUE, "1,2")
            .endObject().endObject()
            .endObject().endObject());

        DocumentMapper defaultMapper = createIndex("test").mapperService().documentMapperParser()
            .parse("type", new CompressedXContent(mapping));
        FieldMapper fieldMapper = defaultMapper.mappers().getMapper("location");
        assertThat(fieldMapper, instanceOf(GeoPointFieldMapper.class));

        Object nullValue = fieldMapper.fieldType().nullValue();
        assertThat(nullValue, equalTo(new GeoPoint(1, 2)));

        ParsedDocument doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                    .startObject()
                    .nullField("location")
                    .endObject()),
            XContentType.JSON));

        assertThat(doc.rootDoc().getField("location"), notNullValue());
        BytesRef defaultValue = doc.rootDoc().getField("location").binaryValue();

        doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                    .startObject()
                    .field("location", "1, 2")
                    .endObject()),
            XContentType.JSON));
        // Shouldn't matter if we specify the value explicitly or use null value
        assertThat(defaultValue, equalTo(doc.rootDoc().getField("location").binaryValue()));

        doc = defaultMapper.parse(SourceToParse.source("test", "type", "1", BytesReference
                .bytes(XContentFactory.jsonBuilder()
                    .startObject()
                    .field("location", "3, 4")
                    .endObject()),
            XContentType.JSON));
        // Shouldn't matter if we specify the value explicitly or use null value
        assertThat(defaultValue, not(equalTo(doc.rootDoc().getField("location").binaryValue())));
    }

}

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

package org.elasticsearch.test.action.admin.indices.create;

import org.elasticsearch.action.admin.indices.alias.Alias;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.testframework.index.RandomCreateIndexGenerator;
import org.elasticsearch.testframework.ESTestCase;
import org.elasticsearch.testframework.hamcrest.ElasticsearchAssertions;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import static org.elasticsearch.cluster.metadata.IndexMetaData.SETTING_NUMBER_OF_SHARDS;
import static org.elasticsearch.common.xcontent.ToXContent.EMPTY_PARAMS;

public class CreateIndexRequestTests extends ESTestCase {

    public void testSerialization() throws IOException {
        CreateIndexRequest request = new CreateIndexRequest("foo");
        String mapping = Strings.toString(JsonXContent.contentBuilder().startObject().startObject("type").endObject().endObject());
        request.mapping("my_type", mapping, XContentType.JSON);

        try (BytesStreamOutput output = new BytesStreamOutput()) {
            request.writeTo(output);

            try (StreamInput in = output.bytes().streamInput()) {
                CreateIndexRequest serialized = new CreateIndexRequest();
                serialized.readFrom(in);
                assertEquals(request.index(), serialized.index());
                assertEquals(mapping, serialized.mappings().get("my_type"));
            }
        }
    }

    public void testToXContent() throws IOException {
        CreateIndexRequest request = new CreateIndexRequest("foo");

        String mapping = Strings.toString(JsonXContent.contentBuilder().startObject().startObject("type").endObject().endObject());
        request.mapping("my_type", mapping, XContentType.JSON);

        Alias alias = new Alias("test_alias");
        alias.routing("1");
        alias.filter("{\"term\":{\"year\":2016}}");
        request.alias(alias);

        Settings.Builder settings = Settings.builder();
        settings.put(SETTING_NUMBER_OF_SHARDS, 10);
        request.settings(settings);

        String actualRequestBody = Strings.toString(request);

        String expectedRequestBody = "{\"settings\":{\"index\":{\"number_of_shards\":\"10\"}}," +
            "\"mappings\":{\"my_type\":{\"type\":{}}}," +
            "\"aliases\":{\"test_alias\":{\"filter\":{\"term\":{\"year\":2016}},\"routing\":\"1\"}}}";

        assertEquals(expectedRequestBody, actualRequestBody);
    }

    public void testToAndFromXContent() throws IOException {

        final CreateIndexRequest createIndexRequest = RandomCreateIndexGenerator.randomCreateIndexRequest();

        boolean humanReadable = randomBoolean();
        final XContentType xContentType = randomFrom(XContentType.values());
        BytesReference originalBytes = toShuffledXContent(createIndexRequest, xContentType, EMPTY_PARAMS, humanReadable);

        CreateIndexRequest parsedCreateIndexRequest = new CreateIndexRequest();
        parsedCreateIndexRequest.source(originalBytes, xContentType);

        assertMappingsEqual(createIndexRequest.mappings(), parsedCreateIndexRequest.mappings());
        assertAliasesEqual(createIndexRequest.aliases(), parsedCreateIndexRequest.aliases());
        assertEquals(createIndexRequest.settings(), parsedCreateIndexRequest.settings());

        BytesReference finalBytes = toShuffledXContent(parsedCreateIndexRequest, xContentType, EMPTY_PARAMS, humanReadable);
        ElasticsearchAssertions.assertToXContentEquivalent(originalBytes, finalBytes, xContentType);
    }

    public static void assertMappingsEqual(Map<String, String> expected, Map<String, String> actual) throws IOException {
        assertEquals(expected.keySet(), actual.keySet());

        for (Map.Entry<String, String> expectedEntry : expected.entrySet()) {
            String expectedValue = expectedEntry.getValue();
            String actualValue = actual.get(expectedEntry.getKey());
            XContentParser expectedJson = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, expectedValue);
            XContentParser actualJson = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, actualValue);
            assertEquals(expectedJson.map(), actualJson.map());
        }
    }

    public static void assertAliasesEqual(Set<Alias> expected, Set<Alias> actual) throws IOException {
        assertEquals(expected, actual);

        for (Alias expectedAlias : expected) {
            for (Alias actualAlias : actual) {
                if (expectedAlias.equals(actualAlias)) {
                    // As Alias#equals only looks at name, we check the equality of the other Alias parameters here.
                    assertEquals(expectedAlias.filter(), actualAlias.filter());
                    assertEquals(expectedAlias.indexRouting(), actualAlias.indexRouting());
                    assertEquals(expectedAlias.searchRouting(), actualAlias.searchRouting());
                }
            }
        }
    }
}

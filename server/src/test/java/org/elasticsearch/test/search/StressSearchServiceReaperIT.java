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
package org.elasticsearch.test.search;

import org.apache.lucene.testframework.util.English;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.search.SearchService;
import org.elasticsearch.testframework.ESIntegTestCase;
import org.elasticsearch.testframework.ESIntegTestCase.ClusterScope;

import java.util.concurrent.ExecutionException;

import static org.elasticsearch.index.query.QueryBuilders.matchAllQuery;
import static org.elasticsearch.testframework.ESIntegTestCase.Scope.SUITE;
import static org.elasticsearch.testframework.hamcrest.ElasticsearchAssertions.assertHitCount;
import static org.elasticsearch.testframework.hamcrest.ElasticsearchAssertions.assertNoFailures;

@ClusterScope(scope = SUITE)
public class StressSearchServiceReaperIT extends ESIntegTestCase {

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        // very frequent checks
        return Settings.builder().put(super.nodeSettings(nodeOrdinal))
                .put(SearchService.KEEPALIVE_INTERVAL_SETTING.getKey(), TimeValue.timeValueMillis(1)).build();
    }

    // see issue #5165 - this test fails each time without the fix in pull #5170
    public void testStressReaper() throws ExecutionException, InterruptedException {
        int num = randomIntBetween(100, 150);
        IndexRequestBuilder[] builders = new IndexRequestBuilder[num];
        for (int i = 0; i < builders.length; i++) {
            builders[i] = client().prepareIndex("test", "type", "" + i).setSource("f", English.intToEnglish(i));
        }
        createIndex("test");
        indexRandom(true, builders);
        final int iterations = scaledRandomIntBetween(500, 1000);
        for (int i = 0; i < iterations; i++) {
            SearchResponse searchResponse = client().prepareSearch("test").setQuery(matchAllQuery()).setSize(num).get();
            assertNoFailures(searchResponse);
            assertHitCount(searchResponse, num);
        }
    }
}

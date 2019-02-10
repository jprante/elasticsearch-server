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

package org.elasticsearch.test.action.bulk;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.bulk.TransportBulkAction;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.AtomicArray;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.index.VersionType;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.testframework.ESTestCase;
import org.elasticsearch.transport.TransportService;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static org.mockito.Mockito.mock;

public class TransportBulkActionIndicesThatCannotBeCreatedTests extends ESTestCase {
    public void testNonExceptional() {
        BulkRequest bulkRequest = new BulkRequest();
        bulkRequest.add(new IndexRequest(randomAlphaOfLength(5)));
        bulkRequest.add(new IndexRequest(randomAlphaOfLength(5)));
        bulkRequest.add(new DeleteRequest(randomAlphaOfLength(5)));
        bulkRequest.add(new UpdateRequest(randomAlphaOfLength(5), randomAlphaOfLength(5), randomAlphaOfLength(5)));
        // Test emulating auto_create_index=false
        indicesThatCannotBeCreatedTestCase(emptySet(), bulkRequest, null);
        // Test emulating auto_create_index=true
        indicesThatCannotBeCreatedTestCase(emptySet(), bulkRequest, index -> true);
        // Test emulating all indices already created
        indicesThatCannotBeCreatedTestCase(emptySet(), bulkRequest, index -> false);
        // Test emulating auto_create_index=true with some indices already created.
        indicesThatCannotBeCreatedTestCase(emptySet(), bulkRequest, index -> randomBoolean());
    }

    public void testAllFail() {
        BulkRequest bulkRequest = new BulkRequest();
        bulkRequest.add(new IndexRequest("no"));
        bulkRequest.add(new IndexRequest("can't"));
        bulkRequest.add(new DeleteRequest("do").version(0).versionType(VersionType.EXTERNAL));
        bulkRequest.add(new UpdateRequest("nothin", randomAlphaOfLength(5), randomAlphaOfLength(5)));
        indicesThatCannotBeCreatedTestCase(new HashSet<>(Arrays.asList("no", "can't", "do", "nothin")), bulkRequest, index -> {
            throw new IndexNotFoundException("Can't make it because I say so");
        });
    }

    public void testSomeFail() {
        BulkRequest bulkRequest = new BulkRequest();
        bulkRequest.add(new IndexRequest("ok"));
        bulkRequest.add(new IndexRequest("bad"));
        // Emulate auto_create_index=-bad,+*
        indicesThatCannotBeCreatedTestCase(singleton("bad"), bulkRequest, index -> {
            if (index.equals("bad")) {
                throw new IndexNotFoundException("Can't make it because I say so");
            }
            return true;
        });
        // Emulate auto_create_index=false but the "ok" index already exists
        indicesThatCannotBeCreatedTestCase(singleton("bad"), bulkRequest, index -> {
            if (index.equals("bad")) {
                throw new IndexNotFoundException("Can't make it because I say so");
            }
            return false;
        });
    }


    private void indicesThatCannotBeCreatedTestCase(Set<String> expected,
            BulkRequest bulkRequest, Function<String, Boolean> shouldAutoCreate) {
        TransportBulkAction action = new TransportBulkAction(Settings.EMPTY, null, mock(TransportService.class), mock(ClusterService.class),
                null, null, null, mock(ActionFilters.class), null, null) {
            @Override
            public void executeBulk(Task task, BulkRequest bulkRequest, long startTimeNanos, ActionListener<BulkResponse> listener,
                             AtomicArray<BulkItemResponse> responses, Map<String, IndexNotFoundException> indicesThatCannotBeCreated) {
                assertEquals(expected, indicesThatCannotBeCreated.keySet());
            }

            @Override
            public boolean needToCheck() {
                return null != shouldAutoCreate; // Use "null" to mean "no indices can be created so don't bother checking"
            }

            @Override
            public boolean shouldAutoCreate(String index, ClusterState state) {
                return shouldAutoCreate.apply(index);
            }

            @Override
            public void createIndex(String index, TimeValue timeout, ActionListener<CreateIndexResponse> listener) {
                // If we try to create an index just immediately assume it worked
                listener.onResponse(new CreateIndexResponse(true, true, index) {});
            }
        };
        action.doExecute(null, bulkRequest, null);
    }
}

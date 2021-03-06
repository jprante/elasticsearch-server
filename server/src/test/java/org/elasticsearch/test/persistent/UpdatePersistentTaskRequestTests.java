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
package org.elasticsearch.test.persistent;

import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.testframework.AbstractStreamableTestCase;
import org.elasticsearch.test.persistent.TestPersistentTasksPlugin.Status;
import org.elasticsearch.test.persistent.TestPersistentTasksPlugin.TestPersistentTasksExecutor;
import org.elasticsearch.persistent.UpdatePersistentTaskStatusAction.Request;

import java.util.Collections;

public class UpdatePersistentTaskRequestTests extends AbstractStreamableTestCase<Request> {

    @Override
    protected Request createTestInstance() {
        return new Request(UUIDs.base64UUID(), randomLong(), new Status(randomAlphaOfLength(10)));
    }

    @Override
    protected Request createBlankInstance() {
        return new Request();
    }

    @Override
    protected NamedWriteableRegistry getNamedWriteableRegistry() {
        return new NamedWriteableRegistry(Collections.singletonList(
                new NamedWriteableRegistry.Entry(Task.Status.class, TestPersistentTasksExecutor.NAME, Status::new)
        ));
    }
}

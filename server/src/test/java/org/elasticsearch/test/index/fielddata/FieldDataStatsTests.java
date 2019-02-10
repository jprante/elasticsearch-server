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
package org.elasticsearch.test.index.fielddata;

import org.elasticsearch.common.FieldMemoryStats;
import org.elasticsearch.index.fielddata.FieldDataStats;
import org.elasticsearch.test.common.FieldMemoryStatsTests;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.testframework.ESTestCase;

import java.io.IOException;

public class FieldDataStatsTests extends ESTestCase {

    public void testSerialize() throws IOException {
        FieldMemoryStats map = randomBoolean() ? null : FieldMemoryStatsTests.randomFieldMemoryStats();
        FieldDataStats stats = new FieldDataStats(randomNonNegativeLong(), randomNonNegativeLong(), map == null ? null :
            map);
        BytesStreamOutput out = new BytesStreamOutput();
        stats.writeTo(out);
        FieldDataStats read = new FieldDataStats();
        StreamInput input = out.bytes().streamInput();
        read.readFrom(input);
        assertEquals(-1, input.read());
        assertEquals(stats.evictions, read.evictions);
        assertEquals(stats.memorySize, read.memorySize);
        assertEquals(stats.getFields(), read.getFields());
    }
}

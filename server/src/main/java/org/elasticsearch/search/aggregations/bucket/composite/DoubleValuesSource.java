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

package org.elasticsearch.search.aggregations.bucket.composite;

import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.search.Query;
import org.elasticsearch.common.CheckedFunction;
import org.elasticsearch.common.lease.Releasables;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.DoubleArray;
import org.elasticsearch.index.fielddata.SortedNumericDoubleValues;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.search.DocValueFormat;
import org.elasticsearch.search.aggregations.LeafBucketCollector;

import java.io.IOException;

/**
 * A {@link SingleDimensionValuesSource} for doubles.
 */
public class DoubleValuesSource extends SingleDimensionValuesSource<Double> {
    private final CheckedFunction<LeafReaderContext, SortedNumericDoubleValues, IOException> docValuesFunc;
    private final DoubleArray values;
    private double currentValue;

    public DoubleValuesSource(BigArrays bigArrays, MappedFieldType fieldType,
                       CheckedFunction<LeafReaderContext, SortedNumericDoubleValues, IOException> docValuesFunc,
                       DocValueFormat format, Object missing, int size, int reverseMul) {
        super(format, fieldType, missing, size, reverseMul);
        this.docValuesFunc = docValuesFunc;
        this.values = bigArrays.newDoubleArray(size, false);
    }

    @Override
    public void copyCurrent(int slot) {
        values.set(slot, currentValue);
    }

    @Override
    public int compare(int from, int to) {
        return compareValues(values.get(from), values.get(to));
    }

    @Override
    public int compareCurrent(int slot) {
        return compareValues(currentValue, values.get(slot));
    }

    @Override
    public int compareCurrentWithAfter() {
        return compareValues(currentValue, afterValue);
    }

    private int compareValues(double v1, double v2) {
        return Double.compare(v1, v2) * reverseMul;
    }

    @Override
    public void setAfter(Comparable<?> value) {
        if (value instanceof Number) {
            afterValue = ((Number) value).doubleValue();
        } else {
            afterValue = format.parseDouble(value.toString(), false, () -> {
                throw new IllegalArgumentException("now() is not supported in [after] key");
            });
        }
    }

    @Override
    public Double toComparable(int slot) {
        return values.get(slot);
    }

    @Override
    public LeafBucketCollector getLeafCollector(LeafReaderContext context, LeafBucketCollector next) throws IOException {
        final SortedNumericDoubleValues dvs = docValuesFunc.apply(context);
        return new LeafBucketCollector() {
            @Override
            public void collect(int doc, long bucket) throws IOException {
                if (dvs.advanceExact(doc)) {
                    int num = dvs.docValueCount();
                    for (int i = 0; i < num; i++) {
                        currentValue = dvs.nextValue();
                        next.collect(doc, bucket);
                    }
                }
            }
        };
    }

    @Override
    public LeafBucketCollector getLeafCollector(Comparable<?> value, LeafReaderContext context, LeafBucketCollector next) {
        if (value.getClass() != Double.class) {
            throw new IllegalArgumentException("Expected Double, got " + value.getClass());
        }
        currentValue = (Double) value;
        return new LeafBucketCollector() {
            @Override
            public void collect(int doc, long bucket) throws IOException {
                next.collect(doc, bucket);
            }
        };
    }

    @Override
    public SortedDocsProducer createSortedDocsProducerOrNull(IndexReader reader, Query query) {
        return null;
    }

    @Override
    public void close() {
        Releasables.close(values);
    }
}

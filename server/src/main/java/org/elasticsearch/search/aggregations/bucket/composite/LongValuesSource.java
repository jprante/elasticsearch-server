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

import org.apache.lucene.document.IntPoint;
import org.apache.lucene.document.LongPoint;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.search.MatchAllDocsQuery;
import org.apache.lucene.search.PointRangeQuery;
import org.apache.lucene.search.Query;
import org.elasticsearch.common.CheckedFunction;
import org.elasticsearch.common.lease.Releasables;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.LongArray;
import org.elasticsearch.index.mapper.DateFieldMapper;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.index.mapper.NumberFieldMapper;
import org.elasticsearch.search.DocValueFormat;
import org.elasticsearch.search.aggregations.LeafBucketCollector;

import java.io.IOException;
import java.util.function.LongUnaryOperator;
import java.util.function.ToLongFunction;

/**
 * A {@link SingleDimensionValuesSource} for longs.
 */
public class LongValuesSource extends SingleDimensionValuesSource<Long> {
    private final CheckedFunction<LeafReaderContext, SortedNumericDocValues, IOException> docValuesFunc;
    private final LongUnaryOperator rounding;

    private final LongArray values;
    private long currentValue;

    public LongValuesSource(BigArrays bigArrays, MappedFieldType fieldType,
                     CheckedFunction<LeafReaderContext, SortedNumericDocValues, IOException> docValuesFunc,
                     LongUnaryOperator rounding, DocValueFormat format, Object missing, int size, int reverseMul) {
        super(format, fieldType, missing, size, reverseMul);
        this.docValuesFunc = docValuesFunc;
        this.rounding = rounding;
        this.values = bigArrays.newLongArray(size, false);
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

    private int compareValues(long v1, long v2) {
        return Long.compare(v1, v2) * reverseMul;
    }

    @Override
    public void setAfter(Comparable<?> value) {
        if (value instanceof Number) {
            afterValue = ((Number) value).longValue();
        } else {
            // for date histogram source with "format", the after value is formatted
            // as a string so we need to retrieve the original value in milliseconds.
            afterValue = format.parseLong(value.toString(), false, () -> {
                throw new IllegalArgumentException("now() is not supported in [after] key");
            });
        }
    }

    @Override
    public Long toComparable(int slot) {
        return values.get(slot);
    }

    @Override
    public LeafBucketCollector getLeafCollector(LeafReaderContext context, LeafBucketCollector next) throws IOException {
        final SortedNumericDocValues dvs = docValuesFunc.apply(context);
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
        if (value.getClass() != Long.class) {
            throw new IllegalArgumentException("Expected Long, got " + value.getClass());
        }
        currentValue = (Long) value;
        return new LeafBucketCollector() {
            @Override
            public void collect(int doc, long bucket) throws IOException {
                next.collect(doc, bucket);
            }
        };
    }

    @Override
    public SortedDocsProducer createSortedDocsProducerOrNull(IndexReader reader, Query query) {
        if (checkIfSortedDocsIsApplicable(reader, fieldType) == false ||
                (query != null &&
                    query.getClass() != MatchAllDocsQuery.class &&
                    // if the query is a range query over the same field
                    (query instanceof PointRangeQuery && fieldType.name().equals((((PointRangeQuery) query).getField()))) == false)) {
            return null;
        }
        final byte[] lowerPoint;
        final byte[] upperPoint;
        if (query instanceof PointRangeQuery) {
            final PointRangeQuery rangeQuery = (PointRangeQuery) query;
            lowerPoint = rangeQuery.getLowerPoint();
            upperPoint = rangeQuery.getUpperPoint();
        } else {
            lowerPoint = null;
            upperPoint = null;
        }

        if (fieldType instanceof NumberFieldMapper.NumberFieldType) {
            NumberFieldMapper.NumberFieldType ft = (NumberFieldMapper.NumberFieldType) fieldType;
            final ToLongFunction<byte[]> toBucketFunction;

            switch (ft.typeName()) {
                case "long":
                    toBucketFunction = (value) -> rounding.applyAsLong(LongPoint.decodeDimension(value, 0));
                    break;

                case "int":
                case "short":
                case "byte":
                    toBucketFunction = (value) -> rounding.applyAsLong(IntPoint.decodeDimension(value, 0));
                    break;

                default:
                    return null;
            }
            return new PointsSortedDocsProducer(fieldType.name(), toBucketFunction, lowerPoint, upperPoint);
        } else if (fieldType instanceof DateFieldMapper.DateFieldType) {
            final ToLongFunction<byte[]> toBucketFunction = (value) -> rounding.applyAsLong(LongPoint.decodeDimension(value, 0));
            return new PointsSortedDocsProducer(fieldType.name(), toBucketFunction, lowerPoint, upperPoint);
        } else {
            return null;
        }
    }

    @Override
    public void close() {
        Releasables.close(values);
    }
}

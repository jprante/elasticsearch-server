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
package org.elasticsearch.search.suggest.phrase;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.Terms;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.script.TemplateScript;
import org.elasticsearch.search.suggest.DirectSpellcheckerSettings;
import org.elasticsearch.search.suggest.SuggestionSearchContext.SuggestionContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PhraseSuggestionContext extends SuggestionContext {
    public static final boolean DEFAULT_COLLATE_PRUNE = false;
    public static final boolean DEFAULT_REQUIRE_UNIGRAM = true;
    public static final float DEFAULT_CONFIDENCE = 1.0f;
    public static final int DEFAULT_GRAM_SIZE = 1;
    public static final float DEFAULT_RWE_ERRORLIKELIHOOD = 0.95f;
    public static final float DEFAULT_MAX_ERRORS = 0.5f;
    public static final String DEFAULT_SEPARATOR = " ";
    public static final WordScorer.WordScorerFactory DEFAULT_SCORER =
            (IndexReader reader, Terms terms, String field, double realWordLikelyhood, BytesRef separator) ->
            new StupidBackoffScorer(reader, terms, field, realWordLikelyhood, separator, 0.4f);

    private float maxErrors = DEFAULT_MAX_ERRORS;
    private BytesRef separator = new BytesRef(DEFAULT_SEPARATOR);
    private float realworldErrorLikelihood = DEFAULT_RWE_ERRORLIKELIHOOD;
    private int gramSize = DEFAULT_GRAM_SIZE;
    private float confidence = DEFAULT_CONFIDENCE;
    private int tokenLimit = NoisyChannelSpellChecker.DEFAULT_TOKEN_LIMIT;
    private boolean requireUnigram = DEFAULT_REQUIRE_UNIGRAM;
    private BytesRef preTag;
    private BytesRef postTag;
    private TemplateScript.Factory scriptFactory;
    private boolean prune = DEFAULT_COLLATE_PRUNE;
    private List<DirectCandidateGenerator> generators = new ArrayList<>();
    private Map<String, Object> collateScriptParams = new HashMap<>(1);
    private WordScorer.WordScorerFactory scorer = DEFAULT_SCORER;

    PhraseSuggestionContext(QueryShardContext shardContext) {
        super(PhraseSuggester.INSTANCE, shardContext);
    }

    public float maxErrors() {
        return maxErrors;
    }

    public void setMaxErrors(Float maxErrors) {
        this.maxErrors = maxErrors;
    }

    public BytesRef separator() {
        return separator;
    }

    public void setSeparator(BytesRef separator) {
        this.separator = separator;
    }

    public Float realworldErrorLikelyhood() {
        return realworldErrorLikelihood;
    }

    public void setRealWordErrorLikelihood(Float realworldErrorLikelihood) {
        this.realworldErrorLikelihood = realworldErrorLikelihood;
    }

    public void addGenerator(DirectCandidateGenerator generator) {
        this.generators.add(generator);
    }

    public List<DirectCandidateGenerator> generators() {
        return this.generators ;
    }

    public void setGramSize(int gramSize) {
        this.gramSize = gramSize;
    }

    public int gramSize() {
        return gramSize;
    }

    public float confidence() {
        return confidence;
    }

    public void setConfidence(float confidence) {
        this.confidence = confidence;
    }

    public void setModel(WordScorer.WordScorerFactory scorer) {
        this.scorer = scorer;
    }

    public WordScorer.WordScorerFactory model() {
        return scorer;
    }

    public static class DirectCandidateGenerator extends DirectSpellcheckerSettings {
        private Analyzer preFilter;
        private Analyzer postFilter;
        private String field;
        private int size = 5;

        public String field() {
            return field;
        }

        public void setField(String field) {
            this.field = field;
        }

        public int size() {
            return size;
        }

        public void size(int size) {
            if (size <= 0) {
                throw new IllegalArgumentException("Size must be positive");
            }
            this.size = size;
        }

        public Analyzer preFilter() {
            return preFilter;
        }

        public void preFilter(Analyzer preFilter) {
            this.preFilter = preFilter;
        }

        public Analyzer postFilter() {
            return postFilter;
        }

        public void postFilter(Analyzer postFilter) {
            this.postFilter = postFilter;
        }
    }

    public void setRequireUnigram(boolean requireUnigram) {
        this.requireUnigram  = requireUnigram;
    }

    public boolean getRequireUnigram() {
        return requireUnigram;
    }

    public void setTokenLimit(int tokenLimit) {
        this.tokenLimit = tokenLimit;
    }

    public int getTokenLimit() {
        return tokenLimit;
    }

    public void setPreTag(BytesRef preTag) {
        this.preTag = preTag;
    }

    public BytesRef getPreTag() {
        return preTag;
    }

    public void setPostTag(BytesRef postTag) {
        this.postTag = postTag;
    }

    public BytesRef getPostTag() {
        return postTag;
    }

    public TemplateScript.Factory getCollateQueryScript() {
        return scriptFactory;
    }

    public void setCollateQueryScript(TemplateScript.Factory scriptFactory) {
        this.scriptFactory = scriptFactory;
    }

    public Map<String, Object> getCollateScriptParams() {
        return collateScriptParams;
    }

    public void setCollateScriptParams(Map<String, Object> collateScriptParams) {
        this.collateScriptParams = new HashMap<>(collateScriptParams);
    }

    public void setCollatePrune(boolean prune) {
        this.prune = prune;
    }

    public boolean collatePrune() {
        return prune;
    }
}

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

package org.elasticsearch.action.admin.indices.rollover;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesClusterStateUpdateRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexClusterStateUpdateRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.stats.IndicesStatsResponse;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.ActiveShardCount;
import org.elasticsearch.action.support.ActiveShardsObserver;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.support.master.TransportMasterNodeAction;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.AliasAction;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.IndexTemplateMetaData;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.metadata.MetaDataCreateIndexService;
import org.elasticsearch.cluster.metadata.MetaDataIndexAliasesService;
import org.elasticsearch.cluster.metadata.MetaDataIndexTemplateService;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.index.shard.DocsStats;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.Collections.unmodifiableList;

/**
 * Main class to swap the index pointed to by an alias, given some conditions
 */
public class TransportRolloverAction extends TransportMasterNodeAction<RolloverRequest, RolloverResponse> {

    private static final Pattern INDEX_NAME_PATTERN = Pattern.compile("^.*-\\d+$");
    private final MetaDataCreateIndexService createIndexService;
    private final MetaDataIndexAliasesService indexAliasesService;
    private final ActiveShardsObserver activeShardsObserver;
    private final Client client;

    @Inject
    public TransportRolloverAction(Settings settings, TransportService transportService, ClusterService clusterService,
                                   ThreadPool threadPool, MetaDataCreateIndexService createIndexService,
                                   ActionFilters actionFilters, IndexNameExpressionResolver indexNameExpressionResolver,
                                   MetaDataIndexAliasesService indexAliasesService, Client client) {
        super(settings, RolloverAction.NAME, transportService, clusterService, threadPool, actionFilters, indexNameExpressionResolver,
            RolloverRequest::new);
        this.createIndexService = createIndexService;
        this.indexAliasesService = indexAliasesService;
        this.client = client;
        this.activeShardsObserver = new ActiveShardsObserver(settings, clusterService, threadPool);
    }

    @Override
    protected String executor() {
        // we go async right away
        return ThreadPool.Names.SAME;
    }

    @Override
    protected RolloverResponse newResponse() {
        return new RolloverResponse();
    }

    @Override
    public ClusterBlockException checkBlock(RolloverRequest request, ClusterState state) {
        IndicesOptions indicesOptions = IndicesOptions.fromOptions(true, true,
            request.indicesOptions().expandWildcardsOpen(), request.indicesOptions().expandWildcardsClosed());
        return state.blocks().indicesBlockedException(ClusterBlockLevel.METADATA_WRITE,
            indexNameExpressionResolver.concreteIndexNames(state, indicesOptions, request.indices()));
    }

    @Override
    public void masterOperation(final RolloverRequest rolloverRequest, final ClusterState state,
                                   final ActionListener<RolloverResponse> listener) {
        final MetaData metaData = state.metaData();
        validate(metaData, rolloverRequest);
        final AliasOrIndex aliasOrIndex = metaData.getAliasAndIndexLookup().get(rolloverRequest.getAlias());
        final IndexMetaData indexMetaData = aliasOrIndex.getIndices().get(0);
        final String sourceProvidedName = indexMetaData.getSettings().get(IndexMetaData.SETTING_INDEX_PROVIDED_NAME,
            indexMetaData.getIndex().getName());
        final String sourceIndexName = indexMetaData.getIndex().getName();
        final String unresolvedName = (rolloverRequest.getNewIndexName() != null)
            ? rolloverRequest.getNewIndexName()
            : generateRolloverIndexName(sourceProvidedName, indexNameExpressionResolver);
        final String rolloverIndexName = indexNameExpressionResolver.resolveDateMathExpression(unresolvedName);
        MetaDataCreateIndexService.validateIndexName(rolloverIndexName, state); // will fail if the index already exists
        checkNoDuplicatedAliasInIndexTemplate(metaData, rolloverIndexName, rolloverRequest.getAlias());
        client.admin().indices().prepareStats(sourceIndexName).clear().setDocs(true).execute(
            new ActionListener<IndicesStatsResponse>() {
                @Override
                public void onResponse(IndicesStatsResponse statsResponse) {
                    final Map<String, Boolean> conditionResults = evaluateConditions(rolloverRequest.getConditions().values(),
                        metaData.index(sourceIndexName), statsResponse);

                    if (rolloverRequest.isDryRun()) {
                        listener.onResponse(
                            new RolloverResponse(sourceIndexName, rolloverIndexName, conditionResults, true, false, false, false));
                        return;
                    }
                    if (conditionResults.size() == 0 || conditionResults.values().stream().anyMatch(result -> result)) {
                        CreateIndexClusterStateUpdateRequest updateRequest = prepareCreateIndexRequest(unresolvedName, rolloverIndexName,
                            rolloverRequest);
                        createIndexService.createIndex(updateRequest, ActionListener.wrap(createIndexClusterStateUpdateResponse -> {
                            // switch the alias to point to the newly created index
                            indexAliasesService.indicesAliases(
                                prepareRolloverAliasesUpdateRequest(sourceIndexName, rolloverIndexName,
                                    rolloverRequest),
                                ActionListener.wrap(aliasClusterStateUpdateResponse -> {
                                    if (aliasClusterStateUpdateResponse.isAcknowledged()) {
                                        activeShardsObserver.waitForActiveShards(new String[]{rolloverIndexName},
                                            rolloverRequest.getCreateIndexRequest().waitForActiveShards(),
                                            rolloverRequest.masterNodeTimeout(),
                                            isShardsAcknowledged -> listener.onResponse(new RolloverResponse(
                                                                sourceIndexName, rolloverIndexName, conditionResults, false, true, true,
                                                                isShardsAcknowledged)),
                                            listener::onFailure);
                                    } else {
                                        listener.onResponse(new RolloverResponse(sourceIndexName, rolloverIndexName, conditionResults,
                                                                                    false, true, false, false));
                                    }
                                }, listener::onFailure));
                        }, listener::onFailure));
                    } else {
                        // conditions not met
                        listener.onResponse(
                            new RolloverResponse(sourceIndexName, rolloverIndexName, conditionResults, false, false, false, false)
                        );
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            }
        );
    }

    public static IndicesAliasesClusterStateUpdateRequest prepareRolloverAliasesUpdateRequest(String oldIndex, String newIndex,
                                                                                       RolloverRequest request) {
        List<AliasAction> actions = unmodifiableList(Arrays.asList(
                new AliasAction.Add(newIndex, request.getAlias(), null, null, null),
                new AliasAction.Remove(oldIndex, request.getAlias())));
        final IndicesAliasesClusterStateUpdateRequest updateRequest = new IndicesAliasesClusterStateUpdateRequest(actions)
            .ackTimeout(request.ackTimeout())
            .masterNodeTimeout(request.masterNodeTimeout());
        return updateRequest;
    }


    public static String generateRolloverIndexName(String sourceIndexName, IndexNameExpressionResolver indexNameExpressionResolver) {
        String resolvedName = indexNameExpressionResolver.resolveDateMathExpression(sourceIndexName);
        final boolean isDateMath = sourceIndexName.equals(resolvedName) == false;
        if (INDEX_NAME_PATTERN.matcher(resolvedName).matches()) {
            int numberIndex = sourceIndexName.lastIndexOf("-");
            assert numberIndex != -1 : "no separator '-' found";
            int counter = Integer.parseInt(sourceIndexName.substring(numberIndex + 1, isDateMath ? sourceIndexName.length()-1 :
                sourceIndexName.length()));
            String newName = sourceIndexName.substring(0, numberIndex) + "-" + String.format(Locale.ROOT, "%06d", ++counter)
                + (isDateMath ? ">" : "");
            return newName;
        } else {
            throw new IllegalArgumentException("index name [" + sourceIndexName + "] does not match pattern '^.*-\\d+$'");
        }
    }

    public static Map<String, Boolean> evaluateConditions(final Collection<Condition> conditions,
                                                   final DocsStats docsStats, final IndexMetaData metaData) {
        final long numDocs = docsStats == null ? 0 : docsStats.getCount();
        final long indexSize = docsStats == null ? 0 : docsStats.getTotalSizeInBytes();
        final Condition.Stats stats = new Condition.Stats(numDocs, metaData.getCreationDate(), new ByteSizeValue(indexSize));
        return conditions.stream()
            .map(condition -> condition.evaluate(stats))
            .collect(Collectors.toMap(result -> result.condition.toString(), result -> result.matched));
    }

    public static Map<String, Boolean> evaluateConditions(final Collection<Condition> conditions, final IndexMetaData metaData,
                                                    final IndicesStatsResponse statsResponse) {
        return evaluateConditions(conditions, statsResponse.getPrimaries().getDocs(), metaData);
    }

    public static void validate(MetaData metaData, RolloverRequest request) {
        final AliasOrIndex aliasOrIndex = metaData.getAliasAndIndexLookup().get(request.getAlias());
        if (aliasOrIndex == null) {
            throw new IllegalArgumentException("source alias does not exist");
        }
        if (aliasOrIndex.isAlias() == false) {
            throw new IllegalArgumentException("source alias is a concrete index");
        }
        if (aliasOrIndex.getIndices().size() != 1) {
            throw new IllegalArgumentException("source alias maps to multiple indices");
        }
    }

    public static CreateIndexClusterStateUpdateRequest prepareCreateIndexRequest(final String providedIndexName,
                                                                                 final String targetIndexName,
                                                                                 final RolloverRequest rolloverRequest) {

        final CreateIndexRequest createIndexRequest = rolloverRequest.getCreateIndexRequest();
        createIndexRequest.cause("rollover_index");
        createIndexRequest.index(targetIndexName);
        return new CreateIndexClusterStateUpdateRequest(createIndexRequest,
            "rollover_index", targetIndexName, providedIndexName, true)
            .ackTimeout(createIndexRequest.timeout())
            .masterNodeTimeout(createIndexRequest.masterNodeTimeout())
            .settings(createIndexRequest.settings())
            .aliases(createIndexRequest.aliases())
            .waitForActiveShards(ActiveShardCount.NONE) // not waiting for shards here, will wait on the alias switch operation
            .mappings(createIndexRequest.mappings());
    }

    /**
     * If the newly created index matches with an index template whose aliases contains the rollover alias,
     * the rollover alias will point to multiple indices. This causes indexing requests to be rejected.
     * To avoid this, we make sure that there is no duplicated alias in index templates before creating a new index.
     */
    public static void checkNoDuplicatedAliasInIndexTemplate(MetaData metaData, String rolloverIndexName, String rolloverRequestAlias) {
        final List<IndexTemplateMetaData> matchedTemplates = MetaDataIndexTemplateService.findTemplates(metaData, rolloverIndexName);
        for (IndexTemplateMetaData template : matchedTemplates) {
            if (template.aliases().containsKey(rolloverRequestAlias)) {
                throw new IllegalArgumentException(String.format(Locale.ROOT,
                    "Rollover alias [%s] can point to multiple indices, found duplicated alias [%s] in index template [%s]",
                    rolloverRequestAlias, template.aliases().keys(), template.name()));
            }
        }
    }
}

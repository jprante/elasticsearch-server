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

package org.elasticsearch.test.cluster.metadata;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.template.delete.DeleteIndexTemplateRequest;
import org.elasticsearch.action.admin.indices.template.delete.DeleteIndexTemplateResponse;
import org.elasticsearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.elasticsearch.action.admin.indices.template.put.PutIndexTemplateResponse;
import org.elasticsearch.client.AdminClient;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.IndicesAdminClient;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexTemplateMetaData;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.metadata.TemplateUpgradeService;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.testframework.ESTestCase;
import org.elasticsearch.testframework.threadpool.TestThreadPool;
import org.elasticsearch.threadpool.ThreadPool;
import org.junit.After;
import org.junit.Before;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.Collections.emptyMap;
import static org.elasticsearch.testframework.ClusterServiceUtils.createClusterService;
import static org.elasticsearch.testframework.ClusterServiceUtils.setState;
import static org.elasticsearch.testframework.VersionUtils.randomVersion;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class TemplateUpgradeServiceTests extends ESTestCase {

    private ThreadPool threadPool;
    private ClusterService clusterService;

    @Before
    public void setUpTest() throws Exception {
        threadPool = new TestThreadPool("TemplateUpgradeServiceTests");
        clusterService = createClusterService(threadPool);
    }

    @After
    public void tearDownTest() throws Exception {
        threadPool.shutdownNow();
        clusterService.close();
    }

    public void testCalculateChangesAddChangeAndDelete() {

        boolean shouldAdd = randomBoolean();
        boolean shouldRemove = randomBoolean();
        boolean shouldChange = randomBoolean();

        MetaData metaData = randomMetaData(
            IndexTemplateMetaData.builder("user_template").patterns(randomIndexPatterns()).build(),
            IndexTemplateMetaData.builder("removed_test_template").patterns(randomIndexPatterns()).build(),
            IndexTemplateMetaData.builder("changed_test_template").patterns(randomIndexPatterns()).build()
        );

        final TemplateUpgradeService service = new TemplateUpgradeService(Settings.EMPTY, null, clusterService, threadPool,
            Arrays.asList(
                templates -> {
                    if (shouldAdd) {
                        assertNull(templates.put("added_test_template",
                            IndexTemplateMetaData.builder("added_test_template").patterns(randomIndexPatterns()).build()));
                    }
                    return templates;
                },
                templates -> {
                    if (shouldRemove) {
                        assertNotNull(templates.remove("removed_test_template"));
                    }
                    return templates;
                },
                templates -> {
                    if (shouldChange) {
                        assertNotNull(templates.put("changed_test_template",
                            IndexTemplateMetaData.builder("changed_test_template").patterns(randomIndexPatterns()).order(10).build()));
                    }
                    return templates;
                }
            ));

        Optional<Tuple<Map<String, BytesReference>, Set<String>>> optChanges =
            service.calculateTemplateChanges(metaData.templates());

        if (shouldAdd || shouldRemove || shouldChange) {
            Tuple<Map<String, BytesReference>, Set<String>> changes = optChanges.orElseThrow(() ->
                new AssertionError("Should have non empty changes"));
            if (shouldAdd) {
                assertThat(changes.v1().get("added_test_template"), notNullValue());
                if (shouldChange) {
                    assertThat(changes.v1().keySet(), hasSize(2));
                    assertThat(changes.v1().get("changed_test_template"), notNullValue());
                } else {
                    assertThat(changes.v1().keySet(), hasSize(1));
                }
            } else {
                if (shouldChange) {
                    assertThat(changes.v1().get("changed_test_template"), notNullValue());
                    assertThat(changes.v1().keySet(), hasSize(1));
                } else {
                    assertThat(changes.v1().keySet(), empty());
                }
            }

            if (shouldRemove) {
                assertThat(changes.v2(), hasSize(1));
                assertThat(changes.v2().contains("removed_test_template"), equalTo(true));
            } else {
                assertThat(changes.v2(), empty());
            }
        } else {
            assertThat(optChanges.isPresent(), equalTo(false));
        }
    }


    @SuppressWarnings("unchecked")
    public void testUpdateTemplates() {
        int additionsCount = randomIntBetween(0, 5);
        int deletionsCount = randomIntBetween(0, 3);

        List<ActionListener<PutIndexTemplateResponse>> putTemplateListeners = new ArrayList<>();
        List<ActionListener<DeleteIndexTemplateResponse>> deleteTemplateListeners = new ArrayList<>();

        Client mockClient = mock(Client.class);
        AdminClient mockAdminClient = mock(AdminClient.class);
        IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
        when(mockClient.admin()).thenReturn(mockAdminClient);
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            PutIndexTemplateRequest request = (PutIndexTemplateRequest) args[0];
            assertThat(request.name(), equalTo("add_template_" + request.order()));
            putTemplateListeners.add((ActionListener) args[1]);
            return null;
        }).when(mockIndicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class), any(ActionListener.class));

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            DeleteIndexTemplateRequest request = (DeleteIndexTemplateRequest) args[0];
            assertThat(request.name(), startsWith("remove_template_"));
            deleteTemplateListeners.add((ActionListener) args[1]);
            return null;
        }).when(mockIndicesAdminClient).deleteTemplate(any(DeleteIndexTemplateRequest.class), any(ActionListener.class));

        Set<String> deletions = new HashSet<>(deletionsCount);
        for (int i = 0; i < deletionsCount; i++) {
            deletions.add("remove_template_" + i);
        }
        Map<String, BytesReference> additions = new HashMap<>(additionsCount);
        for (int i = 0; i < additionsCount; i++) {
            additions.put("add_template_" + i, new BytesArray("{\"index_patterns\" : \"*\", \"order\" : " + i + "}"));
        }

        final TemplateUpgradeService service = new TemplateUpgradeService(Settings.EMPTY, mockClient, clusterService, threadPool,
            Collections.emptyList());

        IllegalStateException ise = expectThrows(IllegalStateException.class, () -> service.upgradeTemplates(additions, deletions));
        assertThat(ise.getMessage(), containsString("template upgrade service should always happen in a system context"));

        service.upgradesInProgress.set(additionsCount + deletionsCount + 2); // +2 to skip tryFinishUpgrade
        final ThreadContext threadContext = threadPool.getThreadContext();
        try (ThreadContext.StoredContext ignore = threadContext.stashContext()) {
            threadContext.markAsSystemContext();
            service.upgradeTemplates(additions, deletions);
        }

        assertThat(putTemplateListeners, hasSize(additionsCount));
        assertThat(deleteTemplateListeners, hasSize(deletionsCount));

        for (int i = 0; i < additionsCount; i++) {
            if (randomBoolean()) {
                putTemplateListeners.get(i).onFailure(new RuntimeException("test - ignore"));
            } else {
                putTemplateListeners.get(i).onResponse(new PutIndexTemplateResponse(randomBoolean()) {

                });
            }
        }

        for (int i = 0; i < deletionsCount; i++) {
            if (randomBoolean()) {
                int prevUpdatesInProgress = service.upgradesInProgress.get();
                deleteTemplateListeners.get(i).onFailure(new RuntimeException("test - ignore"));
                assertThat(prevUpdatesInProgress - service.upgradesInProgress.get(), equalTo(1));
            } else {
                int prevUpdatesInProgress = service.upgradesInProgress.get();
                deleteTemplateListeners.get(i).onResponse(new DeleteIndexTemplateResponse(randomBoolean()) {

                });
                assertThat(prevUpdatesInProgress - service.upgradesInProgress.get(), equalTo(1));
            }
        }
        // tryFinishUpgrade was skipped
        assertThat(service.upgradesInProgress.get(), equalTo(2));
    }

    private static final Set<DiscoveryNode.Role> MASTER_DATA_ROLES =
        Collections.unmodifiableSet(EnumSet.of(DiscoveryNode.Role.MASTER, DiscoveryNode.Role.DATA));

    @SuppressWarnings("unchecked")
    public void testClusterStateUpdate() throws InterruptedException {

        final AtomicReference<ActionListener<PutIndexTemplateResponse>> addedListener = new AtomicReference<>();
        final AtomicReference<ActionListener<PutIndexTemplateResponse>> changedListener = new AtomicReference<>();
        final AtomicReference<ActionListener<DeleteIndexTemplateResponse>> removedListener = new AtomicReference<>();
        final Semaphore updateInvocation = new Semaphore(0);
        final Semaphore calculateInvocation = new Semaphore(0);
        final Semaphore changedInvocation = new Semaphore(0);
        final Semaphore finishInvocation = new Semaphore(0);

        MetaData metaData = randomMetaData(
            IndexTemplateMetaData.builder("user_template").patterns(randomIndexPatterns()).build(),
            IndexTemplateMetaData.builder("removed_test_template").patterns(randomIndexPatterns()).build(),
            IndexTemplateMetaData.builder("changed_test_template").patterns(randomIndexPatterns()).build()
        );

        Client mockClient = mock(Client.class);
        AdminClient mockAdminClient = mock(AdminClient.class);
        IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
        when(mockClient.admin()).thenReturn(mockAdminClient);
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            PutIndexTemplateRequest request = (PutIndexTemplateRequest) args[0];
            if (request.name().equals("added_test_template")) {
                assertThat(addedListener.getAndSet((ActionListener) args[1]), nullValue());
            } else if (request.name().equals("changed_test_template")) {
                assertThat(changedListener.getAndSet((ActionListener) args[1]), nullValue());
            } else {
                fail("unexpected put template call for " + request.name());
            }
            return null;
        }).when(mockIndicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class), any(ActionListener.class));

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            DeleteIndexTemplateRequest request = (DeleteIndexTemplateRequest) args[0];
            assertThat(request.name(), startsWith("removed_test_template"));
            assertThat(removedListener.getAndSet((ActionListener) args[1]), nullValue());
            return null;
        }).when(mockIndicesAdminClient).deleteTemplate(any(DeleteIndexTemplateRequest.class), any(ActionListener.class));

        final TemplateUpgradeService service = new TemplateUpgradeService(Settings.EMPTY, mockClient, clusterService, threadPool,
            Arrays.asList(
                templates -> {
                    assertNull(templates.put("added_test_template", IndexTemplateMetaData.builder("added_test_template")
                        .patterns(Collections.singletonList("*")).build()));
                    return templates;
                },
                templates -> {
                    assertNotNull(templates.remove("removed_test_template"));
                    return templates;
                },
                templates -> {
                    assertNotNull(templates.put("changed_test_template", IndexTemplateMetaData.builder("changed_test_template")
                        .patterns(Collections.singletonList("*")).order(10).build()));
                    return templates;
                }
                )) {

            @Override
            public void tryFinishUpgrade(AtomicBoolean anyUpgradeFailed) {
                super.tryFinishUpgrade(anyUpgradeFailed);
                finishInvocation.release();
            }

            @Override
            public void upgradeTemplates(Map<String, BytesReference> changes, Set<String> deletions) {
                super.upgradeTemplates(changes, deletions);
                updateInvocation.release();
            }

            @Override
            public Optional<Tuple<Map<String, BytesReference>, Set<String>>>
                    calculateTemplateChanges(ImmutableOpenMap<String, IndexTemplateMetaData> templates) {
                final Optional<Tuple<Map<String, BytesReference>, Set<String>>> ans = super.calculateTemplateChanges(templates);
                calculateInvocation.release();
                return ans;
            }

            @Override
            public void clusterChanged(ClusterChangedEvent event) {
                super.clusterChanged(event);
                changedInvocation.release();
            }
        };

        ClusterState prevState = ClusterState.EMPTY_STATE;
        ClusterState state = ClusterState.builder(prevState).nodes(DiscoveryNodes.builder()
            .add(new DiscoveryNode("node1", "node1", buildNewFakeTransportAddress(), emptyMap(), MASTER_DATA_ROLES, Version.CURRENT)
            ).localNodeId("node1").masterNodeId("node1").build()
        ).metaData(metaData).build();
        setState(clusterService, state);

        changedInvocation.acquire();
        assertThat(changedInvocation.availablePermits(), equalTo(0));
        calculateInvocation.acquire();
        assertThat(calculateInvocation.availablePermits(), equalTo(0));
        updateInvocation.acquire();
        assertThat(updateInvocation.availablePermits(), equalTo(0));
        assertThat(finishInvocation.availablePermits(), equalTo(0));
        assertThat(addedListener.get(), notNullValue());
        assertThat(changedListener.get(), notNullValue());
        assertThat(removedListener.get(), notNullValue());

        prevState = state;
        state = ClusterState.builder(prevState).metaData(MetaData.builder(state.metaData()).removeTemplate("user_template")).build();
        setState(clusterService, state);

        // Make sure that update wasn't invoked since we are still running
        changedInvocation.acquire();
        assertThat(changedInvocation.availablePermits(), equalTo(0));
        assertThat(calculateInvocation.availablePermits(), equalTo(0));
        assertThat(updateInvocation.availablePermits(), equalTo(0));
        assertThat(finishInvocation.availablePermits(), equalTo(0));

        addedListener.getAndSet(null).onResponse(new PutIndexTemplateResponse(true) {
        });
        changedListener.getAndSet(null).onResponse(new PutIndexTemplateResponse(true) {
        });
        removedListener.getAndSet(null).onResponse(new DeleteIndexTemplateResponse(true) {
        });

        // 3 upgrades should be completed, in addition to the final calculate
        finishInvocation.acquire(3);
        assertThat(finishInvocation.availablePermits(), equalTo(0));
        calculateInvocation.acquire();
        assertThat(calculateInvocation.availablePermits(), equalTo(0));

        setState(clusterService, state);

        // Make sure that update was called this time since we are no longer running
        changedInvocation.acquire();
        assertThat(changedInvocation.availablePermits(), equalTo(0));
        calculateInvocation.acquire();
        assertThat(calculateInvocation.availablePermits(), equalTo(0));
        updateInvocation.acquire();
        assertThat(updateInvocation.availablePermits(), equalTo(0));
        assertThat(finishInvocation.availablePermits(), equalTo(0));

        addedListener.getAndSet(null).onFailure(new RuntimeException("test - ignore"));
        changedListener.getAndSet(null).onFailure(new RuntimeException("test - ignore"));
        removedListener.getAndSet(null).onFailure(new RuntimeException("test - ignore"));

        finishInvocation.acquire(3);
        assertThat(finishInvocation.availablePermits(), equalTo(0));
        calculateInvocation.acquire();
        assertThat(calculateInvocation.availablePermits(), equalTo(0));

        setState(clusterService, state);

        // Make sure that update wasn't called this time since the index template metadata didn't change
        changedInvocation.acquire();
        assertThat(changedInvocation.availablePermits(), equalTo(0));
        assertThat(calculateInvocation.availablePermits(), equalTo(0));
        assertThat(updateInvocation.availablePermits(), equalTo(0));
        assertThat(finishInvocation.availablePermits(), equalTo(0));
    }

    private static final int NODE_TEST_ITERS = 100;

    private DiscoveryNodes randomNodes(int dataAndMasterNodes, int clientNodes) {
        DiscoveryNodes.Builder builder = DiscoveryNodes.builder();
        String masterNodeId = null;
        for (int i = 0; i < dataAndMasterNodes; i++) {
            String id = randomAlphaOfLength(10) + "_" + i;
            Set<DiscoveryNode.Role> roles;
            if (i == 0) {
                masterNodeId = id;
                // The first node has to be master node
                if (randomBoolean()) {
                    roles = EnumSet.of(DiscoveryNode.Role.MASTER, DiscoveryNode.Role.DATA);
                } else {
                    roles = EnumSet.of(DiscoveryNode.Role.MASTER);
                }
            } else {
                if (randomBoolean()) {
                    roles = EnumSet.of(DiscoveryNode.Role.DATA);
                } else {
                    roles = EnumSet.of(DiscoveryNode.Role.MASTER);
                }
            }
            String node = "node_" + i;
            builder.add(new DiscoveryNode(node, id, buildNewFakeTransportAddress(), emptyMap(), roles, randomVersion(random())));
        }
        builder.masterNodeId(masterNodeId);  // Node 0 is always a master node

        for (int i = 0; i < clientNodes; i++) {
            String node = "client_" + i;
            builder.add(new DiscoveryNode(node, randomAlphaOfLength(10) + "__" + i, buildNewFakeTransportAddress(), emptyMap(),
                EnumSet.noneOf(DiscoveryNode.Role.class), randomVersion(random())));
        }
        return builder.build();
    }

    public static MetaData randomMetaData(IndexTemplateMetaData... templates) {
        MetaData.Builder builder = MetaData.builder();
        for (IndexTemplateMetaData template : templates) {
            builder.put(template);
        }
        for (int i = 0; i < randomIntBetween(1, 5); i++) {
            builder.put(
                IndexMetaData.builder(randomAlphaOfLength(10))
                    .settings(settings(Version.CURRENT))
                    .numberOfReplicas(randomIntBetween(0, 3))
                    .numberOfShards(randomIntBetween(1, 5))
            );
        }
        return builder.build();
    }

    List<String> randomIndexPatterns() {
        return IntStream.range(0, between(1, 10))
            .mapToObj(n -> randomUnicodeOfCodepointLengthBetween(1, 100))
            .collect(Collectors.toList());
    }
}

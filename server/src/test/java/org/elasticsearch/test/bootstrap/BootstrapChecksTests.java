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

package org.elasticsearch.test.bootstrap;

import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.Constants;
import org.elasticsearch.bootstrap.BootstrapCheck;
import org.elasticsearch.bootstrap.BootstrapChecks;
import org.elasticsearch.bootstrap.BootstrapContext;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.BoundTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.monitor.jvm.JvmInfo;
import org.elasticsearch.node.NodeValidationException;
import org.elasticsearch.testframework.ESTestCase;
import org.junit.Ignore;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.Matchers.hasToString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class BootstrapChecksTests extends ESTestCase {

    private static final BootstrapContext defaultContext = new BootstrapContext(Settings.EMPTY, MetaData.EMPTY_META_DATA);

    public void testNonProductionMode() throws NodeValidationException {
        // nothing should happen since we are in non-production mode
        final List<TransportAddress> transportAddresses = new ArrayList<>();
        for (int i = 0; i < randomIntBetween(1, 8); i++) {
            TransportAddress localTransportAddress = new TransportAddress(InetAddress.getLoopbackAddress(), i);
            transportAddresses.add(localTransportAddress);
        }

        TransportAddress publishAddress = new TransportAddress(InetAddress.getLoopbackAddress(), 0);
        BoundTransportAddress boundTransportAddress = mock(BoundTransportAddress.class);
        when(boundTransportAddress.boundAddresses()).thenReturn(transportAddresses.toArray(new TransportAddress[0]));
        when(boundTransportAddress.publishAddress()).thenReturn(publishAddress);
        BootstrapChecks.check(defaultContext, boundTransportAddress, Collections.emptyList());
    }

    public void testNoLogMessageInNonProductionMode() throws NodeValidationException {
        final Logger logger = mock(Logger.class);
        BootstrapChecks.check(defaultContext, false, Collections.emptyList(), logger);
        verifyNoMoreInteractions(logger);
    }

    public void testLogMessageInProductionMode() throws NodeValidationException {
        final Logger logger = mock(Logger.class);
        BootstrapChecks.check(defaultContext, true, Collections.emptyList(), logger);
        verify(logger).info("bound or publishing to a non-loopback address, enforcing bootstrap checks");
        verifyNoMoreInteractions(logger);
    }

    public void testEnforceLimitsWhenBoundToNonLocalAddress() {
        final List<TransportAddress> transportAddresses = new ArrayList<>();
        final TransportAddress nonLocalTransportAddress = buildNewFakeTransportAddress();
        transportAddresses.add(nonLocalTransportAddress);

        for (int i = 0; i < randomIntBetween(0, 7); i++) {
            final TransportAddress randomTransportAddress = randomBoolean() ? buildNewFakeTransportAddress() :
                new TransportAddress(InetAddress.getLoopbackAddress(), i);
            transportAddresses.add(randomTransportAddress);
        }

        final TransportAddress publishAddress = randomBoolean() ? buildNewFakeTransportAddress() :
            new TransportAddress(InetAddress.getLoopbackAddress(), 0);

        final BoundTransportAddress boundTransportAddress = mock(BoundTransportAddress.class);
        Collections.shuffle(transportAddresses, random());
        when(boundTransportAddress.boundAddresses()).thenReturn(transportAddresses.toArray(new TransportAddress[0]));
        when(boundTransportAddress.publishAddress()).thenReturn(publishAddress);

        final String discoveryType = randomFrom("zen", "single-node");

        assertEquals(BootstrapChecks.enforceLimits(boundTransportAddress, discoveryType), !"single-node".equals(discoveryType));
    }

    public void testEnforceLimitsWhenPublishingToNonLocalAddress() {
        final List<TransportAddress> transportAddresses = new ArrayList<>();

        for (int i = 0; i < randomIntBetween(1, 8); i++) {
            final TransportAddress randomTransportAddress = buildNewFakeTransportAddress();
            transportAddresses.add(randomTransportAddress);
        }

        final TransportAddress publishAddress = new TransportAddress(InetAddress.getLoopbackAddress(), 0);
        final BoundTransportAddress boundTransportAddress = mock(BoundTransportAddress.class);
        when(boundTransportAddress.boundAddresses()).thenReturn(transportAddresses.toArray(new TransportAddress[0]));
        when(boundTransportAddress.publishAddress()).thenReturn(publishAddress);

        final String discoveryType = randomFrom("zen", "single-node");

        assertEquals(BootstrapChecks.enforceLimits(boundTransportAddress, discoveryType), !"single-node".equals(discoveryType));
    }

    public void testExceptionAggregation() {
        final List<BootstrapCheck> checks = Arrays.asList(
                context -> BootstrapCheck.BootstrapCheckResult.failure("first"),
                context -> BootstrapCheck.BootstrapCheckResult.failure("second"));

        final NodeValidationException e =
                expectThrows(NodeValidationException.class,
                    () -> BootstrapChecks.check(defaultContext, true, checks, "testExceptionAggregation"));
        assertThat(e, hasToString(allOf(containsString("bootstrap checks failed"), containsString("first"), containsString("second"))));
        final Throwable[] suppressed = e.getSuppressed();
        assertThat(suppressed.length, equalTo(2));
        assertThat(suppressed[0], instanceOf(IllegalStateException.class));
        assertThat(suppressed[0], hasToString(containsString("first")));
        assertThat(suppressed[1], instanceOf(IllegalStateException.class));
        assertThat(suppressed[1], hasToString(containsString("second")));
    }

    public void testFileDescriptorLimits() throws NodeValidationException {
        final boolean osX = randomBoolean(); // simulates OS X versus non-OS X
        final int limit = osX ? 10240 : 1 << 16;
        final AtomicLong maxFileDescriptorCount = new AtomicLong(randomIntBetween(1, limit - 1));
        final BootstrapChecks.FileDescriptorCheck check;
        if (osX) {
            check = new BootstrapChecks.OsXFileDescriptorCheck() {
                @Override
                public long getMaxFileDescriptorCount() {
                    return maxFileDescriptorCount.get();
                }
            };
        } else {
            check = new BootstrapChecks.FileDescriptorCheck() {
                @Override
                public long getMaxFileDescriptorCount() {
                    return maxFileDescriptorCount.get();
                }
            };
        }

        final NodeValidationException e =
                expectThrows(NodeValidationException.class,
                        () -> BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testFileDescriptorLimits"));
        assertThat(e.getMessage(), containsString("max file descriptors"));

        maxFileDescriptorCount.set(randomIntBetween(limit + 1, Integer.MAX_VALUE));

        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testFileDescriptorLimits");

        // nothing should happen if current file descriptor count is
        // not available
        maxFileDescriptorCount.set(-1);
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testFileDescriptorLimits");
    }

    public void testFileDescriptorLimitsThrowsOnInvalidLimit() {
        final IllegalArgumentException e =
            expectThrows(
                IllegalArgumentException.class,
                () -> new BootstrapChecks.FileDescriptorCheck(-randomIntBetween(0, Integer.MAX_VALUE)));
        assertThat(e.getMessage(), containsString("limit must be positive but was"));
    }

    public void testMlockallCheck() throws NodeValidationException {
        class MlockallCheckTestCase {

            private final boolean mlockallSet;
            private final boolean isMemoryLocked;
            private final boolean shouldFail;

            MlockallCheckTestCase(final boolean mlockallSet, final boolean isMemoryLocked, final boolean shouldFail) {
                this.mlockallSet = mlockallSet;
                this.isMemoryLocked = isMemoryLocked;
                this.shouldFail = shouldFail;
            }

        }

        final List<MlockallCheckTestCase> testCases = new ArrayList<>();
        testCases.add(new MlockallCheckTestCase(true, true, false));
        testCases.add(new MlockallCheckTestCase(true, false, true));
        testCases.add(new MlockallCheckTestCase(false, true, false));
        testCases.add(new MlockallCheckTestCase(false, false, false));

        for (final MlockallCheckTestCase testCase : testCases) {
            final BootstrapChecks.MlockallCheck check = new BootstrapChecks.MlockallCheck() {
                @Override
                public boolean isMemoryLocked() {
                    return testCase.isMemoryLocked;
                }
            };
            BootstrapContext bootstrapContext = new BootstrapContext(
                Settings.builder().put("bootstrap.memory_lock", testCase.mlockallSet).build(), null);
            if (testCase.shouldFail) {
                final NodeValidationException e = expectThrows(
                        NodeValidationException.class,
                        () -> BootstrapChecks.check(
                                bootstrapContext,
                                true,
                                Collections.singletonList(check),
                                "testFileDescriptorLimitsThrowsOnInvalidLimit"));
                assertThat(
                        e.getMessage(),
                        containsString("memory locking requested for elasticsearch process but memory is not locked"));
            } else {
                // nothing should happen
                BootstrapChecks.check(bootstrapContext, true, Collections.singletonList(check),
                    "testFileDescriptorLimitsThrowsOnInvalidLimit");
            }
        }
    }

    public void testMaxNumberOfThreadsCheck() throws NodeValidationException {
        final int limit = 1 << 11;
        final AtomicLong maxNumberOfThreads = new AtomicLong(randomIntBetween(1, limit - 1));
        final BootstrapChecks.MaxNumberOfThreadsCheck check = new BootstrapChecks.MaxNumberOfThreadsCheck() {
            @Override
            public long getMaxNumberOfThreads() {
                return maxNumberOfThreads.get();
            }
        };

        final NodeValidationException e = expectThrows(
                NodeValidationException.class,
                () -> BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxNumberOfThreadsCheck"));
        assertThat(e.getMessage(), containsString("max number of threads"));

        maxNumberOfThreads.set(randomIntBetween(limit + 1, Integer.MAX_VALUE));

        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxNumberOfThreadsCheck");

        // nothing should happen if current max number of threads is
        // not available
        maxNumberOfThreads.set(-1);
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxNumberOfThreadsCheck");
    }

    public void testMaxSizeVirtualMemory() throws NodeValidationException {
        final long rlimInfinity = Constants.MAC_OS_X ? 9223372036854775807L : -1L;
        final AtomicLong maxSizeVirtualMemory = new AtomicLong(randomIntBetween(0, Integer.MAX_VALUE));
        final BootstrapChecks.MaxSizeVirtualMemoryCheck check = new BootstrapChecks.MaxSizeVirtualMemoryCheck() {
            @Override
            public long getMaxSizeVirtualMemory() {
                return maxSizeVirtualMemory.get();
            }

            @Override
            public long getRlimInfinity() {
                return rlimInfinity;
            }
        };

        final NodeValidationException e = expectThrows(
                NodeValidationException.class,
                () -> BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxSizeVirtualMemory"));
        assertThat(e.getMessage(), containsString("max size virtual memory"));

        maxSizeVirtualMemory.set(rlimInfinity);

        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxSizeVirtualMemory");

        // nothing should happen if max size virtual memory is not available
        maxSizeVirtualMemory.set(Long.MIN_VALUE);
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxSizeVirtualMemory");
    }

    public void testMaxFileSizeCheck() throws NodeValidationException {
        final long rlimInfinity = Constants.MAC_OS_X ? 9223372036854775807L : -1L;
        final AtomicLong maxFileSize = new AtomicLong(randomIntBetween(0, Integer.MAX_VALUE));
        final BootstrapChecks.MaxFileSizeCheck check = new BootstrapChecks.MaxFileSizeCheck() {
            @Override
            public long getMaxFileSize() {
                return maxFileSize.get();
            }

            @Override
            public long getRlimInfinity() {
                return rlimInfinity;
            }
        };

        final NodeValidationException e = expectThrows(
                NodeValidationException.class,
                () -> BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxFileSize"));
        assertThat(e.getMessage(), containsString("max file size"));

        maxFileSize.set(rlimInfinity);

        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxFileSize");

        // nothing should happen if max file size is not available
        maxFileSize.set(Long.MIN_VALUE);
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxFileSize");
    }

    @Ignore // we do no longer enfore max map count!
    public void testMaxMapCountCheck() throws NodeValidationException {
        final int limit = 1 << 18;
        final AtomicLong maxMapCount = new AtomicLong(randomIntBetween(1, limit - 1));
        final BootstrapChecks.MaxMapCountCheck check = new BootstrapChecks.MaxMapCountCheck() {
            @Override
            public long getMaxMapCount() {
                return maxMapCount.get();
            }
        };

        final NodeValidationException e = expectThrows(
                NodeValidationException.class,
                () -> BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxMapCountCheck"));
        assertThat(e.getMessage(), containsString("max virtual memory areas vm.max_map_count"));

        maxMapCount.set(randomIntBetween(limit + 1, Integer.MAX_VALUE));

        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxMapCountCheck");

        // nothing should happen if current vm.max_map_count is not
        // available
        maxMapCount.set(-1);
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testMaxMapCountCheck");
    }

    public void testUseSerialGCCheck() throws NodeValidationException {
        final AtomicReference<String> useSerialGC = new AtomicReference<>("true");
        final BootstrapCheck check = new BootstrapChecks.UseSerialGCCheck() {
            @Override
            public String getUseSerialGC() {
                return useSerialGC.get();
            }
        };

        final NodeValidationException e = expectThrows(
            NodeValidationException.class,
            () -> BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testUseSerialGCCheck"));
        assertThat(
            e.getMessage(),
            containsString("JVM is using the serial collector but should not be for the best performance; " + "" +
                "either it's the default for the VM [" + JvmInfo.jvmInfo().getVmName() +"] or -XX:+UseSerialGC was explicitly specified"));

        useSerialGC.set("false");
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), "testUseSerialGCCheck");
    }

    public void testSystemCallFilterCheck() throws NodeValidationException {
        final AtomicBoolean isSystemCallFilterInstalled = new AtomicBoolean();
        BootstrapContext context = randomBoolean() ? new BootstrapContext(Settings.builder().put("bootstrap.system_call_filter", true)
            .build(), null) : defaultContext;

        final BootstrapChecks.SystemCallFilterCheck systemCallFilterEnabledCheck = new BootstrapChecks.SystemCallFilterCheck() {
            @Override
            public boolean isSystemCallFilterInstalled() {
                return isSystemCallFilterInstalled.get();
            }
        };

        final NodeValidationException e = expectThrows(
            NodeValidationException.class,
            () -> BootstrapChecks.check(context, true, Collections.singletonList(systemCallFilterEnabledCheck),
                "testSystemCallFilterCheck"));
        assertThat(
            e.getMessage(),
            containsString("system call filters failed to install; " +
                "check the logs and fix your configuration or disable system call filters at your own risk"));

        isSystemCallFilterInstalled.set(true);
        BootstrapChecks.check(context, true, Collections.singletonList(systemCallFilterEnabledCheck), "testSystemCallFilterCheck");
        BootstrapContext context_1 = new BootstrapContext(Settings.builder().put("bootstrap.system_call_filter", false).build(), null);
        final BootstrapChecks.SystemCallFilterCheck systemCallFilterNotEnabledCheck = new BootstrapChecks.SystemCallFilterCheck() {
            @Override
            public boolean isSystemCallFilterInstalled() {
                return isSystemCallFilterInstalled.get();
            }
        };
        isSystemCallFilterInstalled.set(false);
        BootstrapChecks.check(context_1, true, Collections.singletonList(systemCallFilterNotEnabledCheck), "testSystemCallFilterCheck");
        isSystemCallFilterInstalled.set(true);
        BootstrapChecks.check(context_1, true, Collections.singletonList(systemCallFilterNotEnabledCheck), "testSystemCallFilterCheck");
    }

    public void testMightForkCheck() throws NodeValidationException {
        final AtomicBoolean isSystemCallFilterInstalled = new AtomicBoolean();
        final AtomicBoolean mightFork = new AtomicBoolean();
        final BootstrapChecks.MightForkCheck check = new BootstrapChecks.MightForkCheck() {
            @Override
            public boolean isSystemCallFilterInstalled() {
                return isSystemCallFilterInstalled.get();
            }

            @Override
            public boolean mightFork() {
                return mightFork.get();
            }

            @Override
            public String message(BootstrapContext context) {
                return "error";
            }
        };

        runMightForkTest(
            check,
            isSystemCallFilterInstalled,
            () -> mightFork.set(false),
            () -> mightFork.set(true),
            e -> assertThat(e.getMessage(), containsString("error")));
    }

    public void testOnErrorCheck() throws NodeValidationException {
        final AtomicBoolean isSystemCallFilterInstalled = new AtomicBoolean();
        final AtomicReference<String> onError = new AtomicReference<>();
        final BootstrapChecks.MightForkCheck check = new BootstrapChecks.OnErrorCheck() {
            @Override
            public boolean isSystemCallFilterInstalled() {
                return isSystemCallFilterInstalled.get();
            }

            @Override
            public String onError() {
                return onError.get();
            }
        };

        final String command = randomAlphaOfLength(16);
        runMightForkTest(
            check,
            isSystemCallFilterInstalled,
            () -> onError.set(randomBoolean() ? "" : null),
            () -> onError.set(command),
            e -> assertThat(
                e.getMessage(),
                containsString(
                    "OnError [" + command + "] requires forking but is prevented by system call filters " +
                        "([bootstrap.system_call_filter=true]); upgrade to at least Java 8u92 and use ExitOnOutOfMemoryError")));
    }

    public void testOnOutOfMemoryErrorCheck() throws NodeValidationException {
        final AtomicBoolean isSystemCallFilterInstalled = new AtomicBoolean();
        final AtomicReference<String> onOutOfMemoryError = new AtomicReference<>();
        final BootstrapChecks.MightForkCheck check = new BootstrapChecks.OnOutOfMemoryErrorCheck() {
            @Override
            public boolean isSystemCallFilterInstalled() {
                return isSystemCallFilterInstalled.get();
            }

            @Override
            public String onOutOfMemoryError() {
                return onOutOfMemoryError.get();
            }
        };

        final String command = randomAlphaOfLength(16);
        runMightForkTest(
            check,
            isSystemCallFilterInstalled,
            () -> onOutOfMemoryError.set(randomBoolean() ? "" : null),
            () -> onOutOfMemoryError.set(command),
            e -> assertThat(
                e.getMessage(),
                containsString(
                    "OnOutOfMemoryError [" + command + "]"
                        + " requires forking but is prevented by system call filters ([bootstrap.system_call_filter=true]);"
                        + " upgrade to at least Java 8u92 and use ExitOnOutOfMemoryError")));
    }

    private void runMightForkTest(
        final BootstrapChecks.MightForkCheck check,
        final AtomicBoolean isSystemCallFilterInstalled,
        final Runnable disableMightFork,
        final Runnable enableMightFork,
        final Consumer<NodeValidationException> consumer) throws NodeValidationException {

        final String methodName = Thread.currentThread().getStackTrace()[2].getMethodName();

        // if system call filter is disabled, nothing should happen
        isSystemCallFilterInstalled.set(false);
        if (randomBoolean()) {
            disableMightFork.run();
        } else {
            enableMightFork.run();
        }
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), methodName);

        // if system call filter is enabled, but we will not fork, nothing should
        // happen
        isSystemCallFilterInstalled.set(true);
        disableMightFork.run();
        BootstrapChecks.check(defaultContext, true, Collections.singletonList(check), methodName);

        // if system call filter is enabled, and we might fork, the check should be enforced, regardless of bootstrap checks being enabled
        // or not
        isSystemCallFilterInstalled.set(true);
        enableMightFork.run();

        final NodeValidationException e = expectThrows(
            NodeValidationException.class,
            () -> BootstrapChecks.check(defaultContext, randomBoolean(), Collections.singletonList(check), methodName));
        consumer.accept(e);
    }

    public void testAllPermissionCheck() throws NodeValidationException {
        final AtomicBoolean isAllPermissionGranted = new AtomicBoolean(true);
        final BootstrapChecks.AllPermissionCheck allPermissionCheck = new BootstrapChecks.AllPermissionCheck() {
            @Override
            public boolean isAllPermissionGranted() {
                return isAllPermissionGranted.get();
            }
        };

        final List<BootstrapCheck> checks = Collections.singletonList(allPermissionCheck);
        final NodeValidationException e = expectThrows(
                NodeValidationException.class,
                () -> BootstrapChecks.check(defaultContext, true, checks, "testIsAllPermissionCheck"));
        assertThat(e, hasToString(containsString("granting the all permission effectively disables security")));

        // if all permissions are not granted, nothing should happen
        isAllPermissionGranted.set(false);
        BootstrapChecks.check(defaultContext, true, checks, "testIsAllPermissionCheck");
    }

    public void testAlwaysEnforcedChecks() {
        final BootstrapCheck check = new BootstrapCheck() {
            @Override
            public BootstrapCheckResult check(BootstrapContext context) {
                return BootstrapCheckResult.failure("error");
            }

            @Override
            public boolean alwaysEnforce() {
                return true;
            }
        };

        final NodeValidationException alwaysEnforced = expectThrows(
            NodeValidationException.class,
            () -> BootstrapChecks.check(defaultContext, randomBoolean(), Collections.singletonList(check), "testAlwaysEnforcedChecks"));
        assertThat(alwaysEnforced, hasToString(containsString("error")));
    }

}

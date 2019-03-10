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

package org.elasticsearch.bootstrap;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.apache.lucene.util.Constants;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.transport.BoundTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.discovery.DiscoveryModule;
import org.elasticsearch.monitor.jvm.JvmInfo;
import org.elasticsearch.monitor.process.ProcessProbe;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeValidationException;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AllPermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

/**
 * We enforce bootstrap checks once a node has the transport protocol bound to a non-loopback interface or if the system property {@code
 * es.enforce.bootstrap.checks} is set to {@true}. In this case we assume the node is running in production and all bootstrap checks must
 * pass.
 *
 * Removed checks:
 *   - heap min/max (is managed by Java 11)
 *   - Client JVM (there is no client VM in Java 11)
 *   - G1GC (default on Java 11)
 *
 * Modified checks:
 *   - minimum number of threads to 2048 (on a 32 core machine, it results in 64 threads per core)
 */
public final class BootstrapChecks {

    private BootstrapChecks() {
    }

    static final String ES_ENFORCE_BOOTSTRAP_CHECKS = "es.enforce.bootstrap.checks";

    /**
     * Executes the bootstrap checks if the node has the transport protocol bound to a non-loopback interface. If the system property
     * {@code es.enforce.bootstrap.checks} is set to {@code true} then the bootstrap checks will be enforced regardless of whether or not
     * the transport protocol is bound to a non-loopback interface.
     *
     * @param context              the current node bootstrap context
     * @param boundTransportAddress the node network bindings
     */
    public static void check(final BootstrapContext context, final BoundTransportAddress boundTransportAddress,
                      List<BootstrapCheck> additionalChecks) throws NodeValidationException {
        final List<BootstrapCheck> builtInChecks = checks();
        final List<BootstrapCheck> combinedChecks = new ArrayList<>(builtInChecks);
        combinedChecks.addAll(additionalChecks);
        check(  context,
                enforceLimits(boundTransportAddress, DiscoveryModule.DISCOVERY_TYPE_SETTING.get(context.settings)),
                Collections.unmodifiableList(combinedChecks),
                Node.NODE_NAME_SETTING.get(context.settings));
    }

    /**
     * Executes the provided checks and fails the node if {@code enforceLimits} is {@code true}, otherwise logs warnings. If the system
     * property {@code es.enforce.bootstrap.checks} is set to {@code true} then the bootstrap checks will be enforced regardless of whether
     * or not the transport protocol is bound to a non-loopback interface.
     *
     * @param context        the current node boostrap context
     * @param enforceLimits {@code true} if the checks should be enforced or otherwise warned
     * @param checks        the checks to execute
     * @param nodeName      the node name to be used as a logging prefix
     */
    public static void check(
        final BootstrapContext context,
        final boolean enforceLimits,
        final List<BootstrapCheck> checks,
        final String nodeName) throws NodeValidationException {
        check(context, enforceLimits, checks, Loggers.getLogger(BootstrapChecks.class, nodeName));
    }

    /**
     * Executes the provided checks and fails the node if {@code enforceLimits} is {@code true}, otherwise logs warnings. If the system
     * property {@code es.enforce.bootstrap.checks }is set to {@code true} then the bootstrap checks will be enforced regardless of whether
     * or not the transport protocol is bound to a non-loopback interface.
     *
     * @param context the current node boostrap context
     * @param enforceLimits {@code true} if the checks should be enforced or otherwise warned
     * @param checks        the checks to execute
     * @param logger        the logger to
     */
    public static void check(
            final BootstrapContext context,
            final boolean enforceLimits,
            final List<BootstrapCheck> checks,
            final Logger logger) throws NodeValidationException {
        final List<String> errors = new ArrayList<>();
        final List<String> ignoredErrors = new ArrayList<>();

        final String esEnforceBootstrapChecks = System.getProperty(ES_ENFORCE_BOOTSTRAP_CHECKS);
        final boolean enforceBootstrapChecks;
        if (esEnforceBootstrapChecks == null) {
            enforceBootstrapChecks = false;
        } else if (Boolean.TRUE.toString().equals(esEnforceBootstrapChecks)) {
            enforceBootstrapChecks = true;
        } else {
            final String message =
                    String.format(
                            Locale.ROOT,
                            "[%s] must be [true] but was [%s]",
                            ES_ENFORCE_BOOTSTRAP_CHECKS,
                            esEnforceBootstrapChecks);
            throw new IllegalArgumentException(message);
        }

        if (enforceLimits) {
            logger.info("bound or publishing to a non-loopback address, enforcing bootstrap checks");
        } else if (enforceBootstrapChecks) {
            logger.info("explicitly enforcing bootstrap checks");
        }

        for (final BootstrapCheck check : checks) {
            final BootstrapCheck.BootstrapCheckResult result = check.check(context);
            if (result.isFailure()) {
                if (!(enforceLimits || enforceBootstrapChecks) && !check.alwaysEnforce()) {
                    ignoredErrors.add(result.getMessage());
                } else {
                    errors.add(result.getMessage());
                }
            }
        }

        if (!ignoredErrors.isEmpty()) {
            ignoredErrors.forEach(error -> log(logger, error));
        }

        if (!errors.isEmpty()) {
            final List<String> messages = new ArrayList<>(1 + errors.size());
            messages.add("[" + errors.size() + "] bootstrap checks failed");
            for (int i = 0; i < errors.size(); i++) {
                messages.add("[" + (i + 1) + "]: " + errors.get(i));
            }
            final NodeValidationException ne = new NodeValidationException(String.join("\n", messages));
            errors.stream().map(IllegalStateException::new).forEach(ne::addSuppressed);
            throw ne;
        }
    }

    public static void log(final Logger logger, final String error) {
        logger.warn(error);
    }

    /**
     * Tests if the checks should be enforced.
     *
     * @param boundTransportAddress the node network bindings
     * @param discoveryType the discovery type
     * @return {@code true} if the checks should be enforced
     */
    public static boolean enforceLimits(final BoundTransportAddress boundTransportAddress, final String discoveryType) {
        final Predicate<TransportAddress> isLoopbackAddress = t -> t.address().getAddress().isLoopbackAddress();
        final boolean bound =
                !(Arrays.stream(boundTransportAddress.boundAddresses()).allMatch(isLoopbackAddress) &&
                isLoopbackAddress.test(boundTransportAddress.publishAddress()));
        return bound && !"single-node".equals(discoveryType);
    }

    // the list of checks to execute
    public static List<BootstrapCheck> checks() {
        final List<BootstrapCheck> checks = new ArrayList<>();
        final FileDescriptorCheck fileDescriptorCheck
            = Constants.MAC_OS_X ? new OsXFileDescriptorCheck() : new FileDescriptorCheck();
        checks.add(fileDescriptorCheck);
        checks.add(new MlockallCheck());
        if (Constants.LINUX) {
            checks.add(new MaxNumberOfThreadsCheck());
        }
        if (Constants.LINUX || Constants.MAC_OS_X) {
            checks.add(new MaxSizeVirtualMemoryCheck());
        }
        if (Constants.LINUX || Constants.MAC_OS_X) {
            checks.add(new MaxFileSizeCheck());
        }
        if (Constants.LINUX) {
            checks.add(new MaxMapCountCheck());
        }
        checks.add(new UseSerialGCCheck());
        checks.add(new SystemCallFilterCheck());
        checks.add(new OnErrorCheck());
        checks.add(new OnOutOfMemoryErrorCheck());
        checks.add(new AllPermissionCheck());
        return Collections.unmodifiableList(checks);
    }

    public static class OsXFileDescriptorCheck extends FileDescriptorCheck {

        public OsXFileDescriptorCheck() {
            // see constant OPEN_MAX defined in
            // /usr/include/sys/syslimits.h on OS X and its use in JVM
            // initialization in int os:init_2(void) defined in the JVM
            // code for BSD (contains OS X)
            super(10240);
        }

    }

    public static class FileDescriptorCheck implements BootstrapCheck {

        private final int limit;

        public FileDescriptorCheck() {
            this(1 << 16);
        }

        public FileDescriptorCheck(final int limit) {
            if (limit <= 0) {
                throw new IllegalArgumentException("limit must be positive but was [" + limit + "]");
            }
            this.limit = limit;
        }

        public final BootstrapCheckResult check(BootstrapContext context) {
            final long maxFileDescriptorCount = getMaxFileDescriptorCount();
            if (maxFileDescriptorCount != -1 && maxFileDescriptorCount < limit) {
                final String message = String.format(
                        Locale.ROOT,
                        "max file descriptors [%d] for elasticsearch process is too low, increase to at least [%d]",
                        getMaxFileDescriptorCount(),
                        limit);
                return BootstrapCheckResult.failure(message);
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public long getMaxFileDescriptorCount() {
            return ProcessProbe.getInstance().getMaxFileDescriptorCount();
        }

    }

    public static class MlockallCheck implements BootstrapCheck {

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            if (BootstrapSettings.MEMORY_LOCK_SETTING.get(context.settings) && !isMemoryLocked()) {
                return BootstrapCheckResult.failure("memory locking requested for elasticsearch process but memory is not locked");
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public boolean isMemoryLocked() {
            return Natives.isMemoryLocked();
        }

    }

    public static class MaxNumberOfThreadsCheck implements BootstrapCheck {

        // maximum is 2048 threads, should be enough on 36 core machines
        private static final long MAX_NUMBER_OF_THREADS_THRESHOLD = 2048L;

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            if (getMaxNumberOfThreads() != -1 && getMaxNumberOfThreads() < MAX_NUMBER_OF_THREADS_THRESHOLD) {
                final String message = String.format(
                        Locale.ROOT,
                        "max number of threads [%d] for user [%s] is too low, increase to at least [%d]",
                        getMaxNumberOfThreads(),
                        BootstrapInfo.getSystemProperties().get("user.name"),
                        MAX_NUMBER_OF_THREADS_THRESHOLD);
                return BootstrapCheckResult.failure(message);
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public long getMaxNumberOfThreads() {
            return JNANatives.MAX_NUMBER_OF_THREADS;
        }

    }

    public static class MaxSizeVirtualMemoryCheck implements BootstrapCheck {

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            if (getMaxSizeVirtualMemory() != Long.MIN_VALUE && getMaxSizeVirtualMemory() != getRlimInfinity()) {
                final String message = String.format(
                        Locale.ROOT,
                        "max size virtual memory [%d] for user [%s] is too low, increase to [unlimited]",
                        getMaxSizeVirtualMemory(),
                        BootstrapInfo.getSystemProperties().get("user.name"));
                return BootstrapCheckResult.failure(message);
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public long getRlimInfinity() {
            return JNACLibrary.RLIM_INFINITY;
        }

        public long getMaxSizeVirtualMemory() {
            return JNANatives.MAX_SIZE_VIRTUAL_MEMORY;
        }

    }

    /**
     * Bootstrap check that the maximum file size is unlimited (otherwise Elasticsearch could run in to an I/O exception writing files).
     */
    public static class MaxFileSizeCheck implements BootstrapCheck {

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            final long maxFileSize = getMaxFileSize();
            if (maxFileSize != Long.MIN_VALUE && maxFileSize != getRlimInfinity()) {
                final String message = String.format(
                        Locale.ROOT,
                        "max file size [%d] for user [%s] is too low, increase to [unlimited]",
                        getMaxFileSize(),
                        BootstrapInfo.getSystemProperties().get("user.name"));
                return BootstrapCheckResult.failure(message);
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public long getRlimInfinity() {
            return JNACLibrary.RLIM_INFINITY;
        }

        public long getMaxFileSize() {
            return JNANatives.MAX_FILE_SIZE;
        }

    }

    public static class MaxMapCountCheck implements BootstrapCheck {

        private static final long LIMIT = 65530;

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            if (getMaxMapCount() != -1 && getMaxMapCount() < LIMIT) {
               final String message = String.format(
                        Locale.ROOT,
                        "max virtual memory areas vm.max_map_count [%d] is too low, increase to at least [%d]",
                        getMaxMapCount(),
                        LIMIT);
               return BootstrapCheckResult.failure(message);
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public long getMaxMapCount() {
            return getMaxMapCount(Loggers.getLogger(BootstrapChecks.class));
        }

        public long getMaxMapCount(Logger logger) {
            final Path path = getProcSysVmMaxMapCountPath();
            try (BufferedReader bufferedReader = getBufferedReader(path)) {
                final String rawProcSysVmMaxMapCount = readProcSysVmMaxMapCount(bufferedReader);
                if (rawProcSysVmMaxMapCount != null) {
                    try {
                        return parseProcSysVmMaxMapCount(rawProcSysVmMaxMapCount);
                    } catch (final NumberFormatException e) {
                        logger.warn(() -> new ParameterizedMessage("unable to parse vm.max_map_count [{}]", rawProcSysVmMaxMapCount), e);
                    }
                }
            } catch (final IOException e) {
                logger.warn(() -> new ParameterizedMessage("I/O exception while trying to read [{}]", path), e);
            }
            return -1;
        }

        @SuppressForbidden(reason = "access /proc/sys/vm/max_map_count")
        private Path getProcSysVmMaxMapCountPath() {
            return PathUtils.get("/proc/sys/vm/max_map_count");
        }

        public BufferedReader getBufferedReader(final Path path) throws IOException {
            return Files.newBufferedReader(path);
        }

        public String readProcSysVmMaxMapCount(final BufferedReader bufferedReader) throws IOException {
            return bufferedReader.readLine();
        }

        public long parseProcSysVmMaxMapCount(final String procSysVmMaxMapCount) throws NumberFormatException {
            return Long.parseLong(procSysVmMaxMapCount);
        }

    }

    /**
     * Checks if the serial collector is in use. This collector is single-threaded and devastating
     * for performance and should not be used for a server application like Elasticsearch.
     */
    public static class UseSerialGCCheck implements BootstrapCheck {

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            if (getUseSerialGC().equals("true")) {
                final String message = String.format(
                        Locale.ROOT,
                        "JVM is using the serial collector but should not be for the best performance; " +
                                "either it's the default for the VM [%s] or -XX:+UseSerialGC was explicitly specified",
                        JvmInfo.jvmInfo().getVmName());
                return BootstrapCheckResult.failure(message);
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public String getUseSerialGC() {
            return JvmInfo.jvmInfo().useSerialGC();
        }

    }

    /**
     * Bootstrap check that if system call filters are enabled, then system call filters must have installed successfully.
     */
    public static class SystemCallFilterCheck implements BootstrapCheck {

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            if (BootstrapSettings.SYSTEM_CALL_FILTER_SETTING.get(context.settings) && !isSystemCallFilterInstalled()) {
                final String message =  "system call filters failed to install; " +
                        "check the logs and fix your configuration or disable system call filters at your own risk";
                return BootstrapCheckResult.failure(message);
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public boolean isSystemCallFilterInstalled() {
            return Natives.isSystemCallFilterInstalled();
        }

    }

    public abstract static class MightForkCheck implements BootstrapCheck {

        @Override
        public BootstrapCheckResult check(BootstrapContext context) {
            if (isSystemCallFilterInstalled() && mightFork()) {
                return BootstrapCheckResult.failure(message(context));
            } else {
                return BootstrapCheckResult.success();
            }
        }

        public abstract String message(BootstrapContext context);

        public boolean isSystemCallFilterInstalled() {
            return Natives.isSystemCallFilterInstalled();
        }

        public abstract boolean mightFork();

        @Override
        public final boolean alwaysEnforce() {
            return true;
        }

    }

    public static class OnErrorCheck extends MightForkCheck {

        @Override
        public boolean mightFork() {
            final String onError = onError();
            return onError != null && !onError.equals("");
        }

        public String onError() {
            return JvmInfo.jvmInfo().onError();
        }

        @Override
        public String message(BootstrapContext context) {
            return String.format(
                Locale.ROOT,
                "OnError [%s] requires forking but is prevented by system call filters ([%s=true]);" +
                    " upgrade to at least Java 8u92 and use ExitOnOutOfMemoryError",
                onError(),
                BootstrapSettings.SYSTEM_CALL_FILTER_SETTING.getKey());
        }

    }

    public static class OnOutOfMemoryErrorCheck extends MightForkCheck {

        @Override
        public boolean mightFork() {
            final String onOutOfMemoryError = onOutOfMemoryError();
            return onOutOfMemoryError != null && !onOutOfMemoryError.equals("");
        }

        public String onOutOfMemoryError() {
            return JvmInfo.jvmInfo().onOutOfMemoryError();
        }

        public String message(BootstrapContext context) {
            return String.format(
                Locale.ROOT,
                "OnOutOfMemoryError [%s] requires forking but is prevented by system call filters ([%s=true]);" +
                    " upgrade to at least Java 8u92 and use ExitOnOutOfMemoryError",
                onOutOfMemoryError(),
                BootstrapSettings.SYSTEM_CALL_FILTER_SETTING.getKey());
        }

    }

    public static class AllPermissionCheck implements BootstrapCheck {

        @Override
        public final BootstrapCheckResult check(BootstrapContext context) {
            if (isAllPermissionGranted()) {
                return BootstrapCheck.BootstrapCheckResult.failure("granting the all permission effectively disables security");
            }
            return BootstrapCheckResult.success();
        }

        public boolean isAllPermissionGranted() {
            final SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                try {
                    sm.checkPermission(new AllPermission());
                } catch (final SecurityException e) {
                    return false;
                }
                return true;
            } else {
                return false;
            }
        }

    }

}

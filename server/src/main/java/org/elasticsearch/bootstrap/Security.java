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
import org.elasticsearch.cli.Command;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.http.HttpTransportSettings;
import org.elasticsearch.plugins.PluginInfo;
import org.elasticsearch.plugins.PluginsService;
import org.elasticsearch.secure_sm.SecureSM;
import org.elasticsearch.transport.TcpTransport;

import java.io.IOException;
import java.lang.module.ModuleReference;
import java.lang.module.ResolvedModule;
import java.net.SocketPermission;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.security.Permissions;
import java.security.Policy;
import java.util.AbstractMap;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.elasticsearch.bootstrap.FilePermissionUtils.addDirectoryPath;
import static org.elasticsearch.bootstrap.FilePermissionUtils.addSingleFilePath;

/**
 * Initializes SecurityManager with necessary permissions.
 * <br>
 * <h1>Initialization</h1>
 * The JVM is not initially started with security manager enabled,
 * instead we turn it on early in the startup process. This is a tradeoff
 * between security and ease of use:
 * <ul>
 *   <li>Assigns file permissions to user-configurable paths that can
 *       be specified from the command-line or {@code elasticsearch.yml}.</li>
 *   <li>Allows for some contained usage of native code that would not
 *       otherwise be permitted.</li>
 * </ul>
 * <br>
 * <h1>Permissions</h1>
 * Permissions use a policy file packaged as a resource, this file is
 * also used in tests. File permissions are generated dynamically and
 * combined with this policy file.
 * <p>
 * For each configured path, we ensure it exists and is accessible before
 * granting permissions, otherwise directory creation would require
 * permissions to parent directories.
 * <p>
 * In some exceptional cases, permissions are assigned to specific jars only,
 * when they are so dangerous that general code should not be granted the
 * permission, but there are extenuating circumstances.
 * <p>
 * Scripts (groovy) are assigned minimal permissions. This does not provide adequate
 * sandboxing, as these scripts still have access to ES classes, and could
 * modify members, etc that would cause bad things to happen later on their
 * behalf (no package protections are yet in place, this would need some
 * cleanups to the scripting apis). But still it can provide some defense for users
 * that enable dynamic scripting without being fully aware of the consequences.
 * <br>
 * <h1>Debugging Security</h1>
 * A good place to start when there is a problem is to turn on security debugging:
 * <pre>
 * ES_JAVA_OPTS="-Djava.security.debug=access,failure" bin/elasticsearch
 * </pre>
 * <p>
 * When running tests you have to pass it to the test runner like this:
 * <pre>
 * gradle test -Dtests.jvm.argline="-Djava.security.debug=access,failure" ...
 * </pre>
 * See <a href="https://docs.oracle.com/javase/7/docs/technotes/guides/security/troubleshooting-security.html">
 * Troubleshooting Security</a> for information.
 */
public final class Security {

    private static final Logger logger = ESLoggerFactory.getLogger(Security.class);

    /** no instantiation */
    private Security() {}

    /**
     * Initializes SecurityManager for the environment
     * Can only happen once!
     * @param environment configuration for generating dynamic permissions
     * @param filterBadDefaults true if we should filter out bad java defaults in the system policy.
     */
    public static void configure(Environment environment, boolean filterBadDefaults)
            throws IOException, URISyntaxException {

        // enable security policy: union of template and environment-based paths, and possibly plugin permissions
        Set<URI> modulePath = parseModulePath();
        Map<String, URI> codebase = createCodebase(modulePath);
        Map<String, String> systemProperties = createSystemProperties(codebase);
        setSystemProperties(systemProperties);
        Permissions permissions = createPermissions(modulePath, environment);
        Map<String, Policy> pluginPolicies = getPluginPermissions(environment);
        // restore system properties, might be cleared while plugin security policy setup
        setSystemProperties(systemProperties);
        try {
            ESPolicy policy = createPolicy(permissions, pluginPolicies, filterBadDefaults);
            Policy.setPolicy(policy);
        } finally {
            clearSystemProperties(systemProperties);
        }
        final String[] classesThatCanExit = new String[]{
                        // SecureSM matches class names as regular expressions so we escape the $ that arises from the nested class name
                        ElasticsearchUncaughtExceptionHandler.PrivilegedHaltAction.class.getName().replace("$", "\\$"),
                        Command.class.getName()};
        SecureSM secureSM = new SecureSM(classesThatCanExit);
        // enable security manager
        System.setSecurityManager(secureSM);
        selfTest();
    }

    public static Map<String, URI> createCodebase(Set<URI> uris) throws IOException {
        Map<String, URI> map = new LinkedHashMap<>();
        for (URI uri : uris) {
            String name = PathUtils.get(uri).getFileName().toString();
            if (name.endsWith(".jar")) {
                map.put(name, uri);
            }
        }
        return map;
    }

    /**
     * Jar files listed in {@code codebases} location will be provided to the policy file via
     * a system property of the short name: e.g. <code>${codebase.joda-convert-1.2.jar}</code>
     * would map to full URL.
     * @param codebase the code base
     * @return a system property map
     */
    public static Map<String, String> createSystemProperties(Map<String, URI> codebase) {
        Map<String, String> propertiesSet = new LinkedHashMap<>();
        for (Map.Entry<String, URI> entry : codebase.entrySet()) {
            String name = entry.getKey();
            URI uri = entry.getValue();
            if (name.indexOf("-linux-x86_64.jar") > 0) {
                continue;
            }
            String property = "codebase." + name;
            String aliasProperty = name.endsWith("-tests.jar") ?
                    "codebase." + name.replaceFirst("-\\d+\\.\\d+.*-tests\\.jar", "-tests") :
                    "codebase." + name.replaceFirst("-\\d+\\.\\d+.*\\.jar", "");
            if (!aliasProperty.equals(property)) {
                propertiesSet.put(aliasProperty, uri.toString());
            }
            propertiesSet.put(property, uri.toString());
        }
        return propertiesSet;
    }

    public static void setSystemProperties(Map<String, String> properties) {
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            if (System.getProperty(entry.getKey()) == null) {
                System.setProperty(entry.getKey(), entry.getValue());
            }
        }
    }

    public static void clearSystemProperties(Map<String, String> properties) {
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            System.clearProperty(entry.getKey());
        }
    }

    public static ESPolicy createPolicy(Permissions permissions,
                                         Map<String, Policy> pluginPolicies, boolean filterBadDefaults)
            throws URISyntaxException {
       return new ESPolicy(permissions, pluginPolicies, filterBadDefaults);
    }

    /**
     * Sets properties (codebase URLs) for policy files.
     * we look for matching plugins and set URLs to fit
     */
    @SuppressForbidden(reason = "proper use of URL")
    public static Map<String,Policy> getPluginPermissions(Environment environment) throws IOException {
        Map<String,Policy> map = new HashMap<>();
        // collect up set of plugins and modules by listing directories.
        Set<Path> pluginsAndModules = new LinkedHashSet<>(PluginsService.findPluginDirs(environment.pluginsFile()));
        pluginsAndModules.addAll(PluginsService.findPluginDirs(environment.modulesFile()));

        // now process each one
        for (Path plugin : pluginsAndModules) {
            Path policyFile = plugin.resolve(PluginInfo.ES_PLUGIN_POLICY);
            if (Files.exists(policyFile)) {
                // first get a list of URLs for the plugins' jars:
                // we resolve symlinks so map is keyed on the normalize codebase name
                Set<URI> pluginCodebase = new LinkedHashSet<>(); // order is already lost, but some filesystems have it
                try (DirectoryStream<Path> jarStream = Files.newDirectoryStream(plugin, "*.jar")) {
                    for (Path jar : jarStream) {
                        URI uri = jar.toRealPath().toUri();
                        if (!pluginCodebase.add(uri)) {
                            throw new IllegalStateException("duplicate module in plugin " + plugin + " uri = " + uri);
                        }
                    }
                }
                Map<String, String> systemProperties = createSystemProperties(createCodebase(pluginCodebase));
                setSystemProperties(systemProperties);
                // parse the plugin's policy file into a set of permissions
                logger.info("reading plugin policy: " + policyFile);
                try {
                    Policy policy = ESPolicy.readPolicy(policyFile.toUri());
                    // consult this policy for each of the plugin's jars
                    for (URI uri : pluginCodebase) {
                        if (map.put(uri.getPath(), policy) != null) {
                            // just be paranoid ok?
                            throw new IllegalStateException("per-plugin permissions already granted for jar file: " + uri);
                        }
                    }
                } finally {
                    clearSystemProperties(systemProperties);
                }
            }
        }
        return Collections.unmodifiableMap(map);
    }

    /** returns dynamic Permissions to configured paths and bind ports */
    public static Permissions createPermissions(Set<URI> modulePath, Environment environment) throws IOException {
        Permissions policy = new Permissions();
        addModulePathPermissions(modulePath, policy);
        addFilePermissions(policy, environment);
        addBindPermissions(policy, environment.settings());
        return policy;
    }

    @SuppressForbidden(reason = "accesses fully qualified URIs to configure security")
    public static void addModulePathPermissions(Set<URI> modulePath, Permissions policy) throws IOException {
        for (URI module : modulePath) {
            Path path = PathUtils.get(module);
            // resource itself
            if (Files.isDirectory(path)) {
                addDirectoryPath(policy, "class.path", path, "read,readlink");
            } else {
                addSingleFilePath(policy, path, "read,readlink");
            }
        }
    }

    /**
     * Adds access to all configurable paths.
     */
    private static void addFilePermissions(Permissions policy, Environment environment) throws IOException {
        // read-only dirs
        addDirectoryPath(policy, Environment.PATH_HOME_SETTING.getKey(), environment.binFile(), "read,readlink");
        addDirectoryPath(policy, Environment.PATH_HOME_SETTING.getKey(), environment.libFile(), "read,readlink");
        addDirectoryPath(policy, Environment.PATH_HOME_SETTING.getKey(), environment.modulesFile(), "read,readlink");
        addDirectoryPath(policy, Environment.PATH_HOME_SETTING.getKey(), environment.pluginsFile(), "read,readlink");
        addDirectoryPath(policy, "path.conf'", environment.configFile(), "read,readlink");
        // read-write dirs
        addDirectoryPath(policy, "java.io.tmpdir", environment.tmpFile(), "read,readlink,write,delete");
        addDirectoryPath(policy, Environment.PATH_LOGS_SETTING.getKey(), environment.logsFile(), "read,readlink,write,delete");
        if (environment.sharedDataFile() != null) {
            addDirectoryPath(policy, Environment.PATH_SHARED_DATA_SETTING.getKey(), environment.sharedDataFile(),
                "read,readlink,write,delete");
        }
        final Set<Path> dataFilesPaths = new HashSet<>();
        for (Path path : environment.dataFiles()) {
            addDirectoryPath(policy, Environment.PATH_DATA_SETTING.getKey(), path, "read,readlink,write,delete");
            /*
             * We have to do this after adding the path because a side effect of that is that the directory is created; the Path#toRealPath
             * invocation will fail if the directory does not already exist. We use Path#toRealPath to follow symlinks and handle issues
             * like unicode normalization or case-insensitivity on some filesystems (e.g., the case-insensitive variant of HFS+ on macOS).
             */
            try {
                final Path realPath = path.toRealPath();
                if (!dataFilesPaths.add(realPath)) {
                    throw new IllegalStateException("path [" + realPath + "] is duplicated by [" + path + "]");
                }
            } catch (final IOException e) {
                throw new IllegalStateException("unable to access [" + path + "]", e);
            }
        }
        for (Path path : environment.repoFiles()) {
            addDirectoryPath(policy, Environment.PATH_REPO_SETTING.getKey(), path, "read,readlink,write,delete");
        }
        if (environment.pidFile() != null) {
            // we just need permission to remove the file if its elsewhere.
            addSingleFilePath(policy, environment.pidFile(), "delete");
        }
    }

    /**
     * Add dynamic {@link SocketPermission}s based on HTTP and transport settings.
     *
     * @param policy the {@link Permissions} instance to apply the dynamic {@link SocketPermission}s to.
     * @param settings the {@link Settings} instance to read the HTTP and transport settings from
     */
    private static void addBindPermissions(Permissions policy, Settings settings) {
        addSocketPermissionForHttp(policy, settings);
        addSocketPermissionForTransportProfiles(policy, settings);
        addSocketPermissionForTribeNodes(policy, settings);
    }

    /**
     * Add dynamic {@link SocketPermission} based on HTTP settings.
     *
     * @param policy the {@link Permissions} instance to apply the dynamic {@link SocketPermission}s to.
     * @param settings the {@link Settings} instance to read the HTTP settings from
     */
    private static void addSocketPermissionForHttp(final Permissions policy, final Settings settings) {
        // http is simple
        final String httpRange = HttpTransportSettings.SETTING_HTTP_PORT.get(settings).getPortRangeString();
        addSocketPermissionForPortRange(policy, httpRange);
    }

    /**
     * Add dynamic {@link SocketPermission} based on transport settings. This method will first check if there is a port range specified in
     * the transport profile specified by {@code profileSettings} and will fall back to {@code settings}.
     *
     * @param policy          the {@link Permissions} instance to apply the dynamic {@link SocketPermission}s to
     * @param settings        the {@link Settings} instance to read the transport settings from
     */
    private static void addSocketPermissionForTransportProfiles(final Permissions policy, final Settings settings) {
        // transport is way over-engineered
        Set<TcpTransport.ProfileSettings> profiles = TcpTransport.getProfileSettings(settings);
        Set<String> uniquePortRanges = new HashSet<>();
        // loop through all profiles and add permissions for each one
        for (final TcpTransport.ProfileSettings profile : profiles) {
            if (uniquePortRanges.add(profile.portOrRange)) {
                // profiles fall back to the transport.port if it's not explicit but we want to only add one permission per range
                addSocketPermissionForPortRange(policy, profile.portOrRange);
            }
        }
    }

    /**
     * Add dynamic {@link SocketPermission} based on transport settings.
     *
     * @param policy          the {@link Permissions} instance to apply the dynamic {@link SocketPermission}s to
     * @param settings        the {@link Settings} instance to read the transport settings from
     */
    private static void addSocketPermissionForTransport(final Permissions policy, final Settings settings) {
        final String transportRange = TcpTransport.PORT.get(settings);
        addSocketPermissionForPortRange(policy, transportRange);
    }

    private static void addSocketPermissionForTribeNodes(final Permissions policy, final Settings settings) {
        for (final Settings tribeNodeSettings : settings.getGroups("tribe", true).values()) {
            // tribe nodes have HTTP disabled by default, so we check if HTTP is enabled before granting
            if (NetworkModule.HTTP_ENABLED.exists(tribeNodeSettings) && NetworkModule.HTTP_ENABLED.get(tribeNodeSettings)) {
                addSocketPermissionForHttp(policy, tribeNodeSettings);
            }
            addSocketPermissionForTransport(policy, tribeNodeSettings);
        }
    }

    /**
     * Add dynamic {@link SocketPermission} for the specified port range.
     *
     * @param policy the {@link Permissions} instance to apply the dynamic {@link SocketPermission} to.
     * @param portRange the port range
     */
    private static void addSocketPermissionForPortRange(final Permissions policy, final String portRange) {
        // listen is always called with 'localhost' but use wildcard to be sure, no name service is consulted.
        // see SocketPermission implies() code
        policy.add(new SocketPermission("*:" + portRange, "listen,resolve"));
    }

    /**
     * Ensures configured directory {@code path} exists.
     * @throws IOException if {@code path} exists, but is not a directory, not accessible, or broken symbolic link.
     */
    public static void ensureDirectoryExists(Path path) throws IOException {
        // this isn't atomic, but neither is createDirectories.
        if (Files.isDirectory(path)) {
            // verify access, following links (throws exception if something is wrong)
            // we only check READ as a sanity test
            path.getFileSystem().provider().checkAccess(path.toRealPath(), AccessMode.READ);
        } else {
            // doesn't exist, or not a directory
            try {
                Files.createDirectories(path);
            } catch (FileAlreadyExistsException e) {
                // convert optional specific exception so the context is clear
                IOException e2 = new NotDirectoryException(path.toString());
                e2.addSuppressed(e);
                throw e2;
            }
        }
    }

    /** Simple checks that everything is ok */
    @SuppressForbidden(reason = "accesses jvm default tempdir as a self-test")
    public static void selfTest() throws IOException {
        // check we can manipulate temporary files
        try {
            Path p = Files.createTempFile(null, null);
            try {
                Files.delete(p);
            } catch (IOException ignored) {
                // potentially virus scanner
            }
        } catch (SecurityException problem) {
            throw new SecurityException("Security misconfiguration: cannot access java.io.tmpdir", problem);
        }
    }

    public static Set<URI> parseModulePath() {
        Deque<ModuleLayer> layerOrder = new ArrayDeque<>();
        Set<ModuleLayer> layerVisited = new HashSet<>();
        CallerResolver callerResolver = new CallerResolver();
        Class<?>[] callStack = callerResolver.getClassContext();
        for (Class<?> cl : callStack) {
            ModuleLayer layer = cl.getModule().getLayer();
            if (layer != null) {
                findLayerOrder(layer, layerVisited, layerOrder);
            }
        }
        ModuleLayer bootLayer = ModuleLayer.boot();
        findLayerOrder(bootLayer, layerVisited, layerOrder);
        Set<ModuleReference> addedModules = new HashSet<>();
        List<Map.Entry<ModuleReference, ModuleLayer>> nonSystemModuleRefs = new ArrayList<>();
        for (ModuleLayer layer : layerOrder) {
            List<ResolvedModule> modulesInLayer = new ArrayList<>(layer.configuration().modules());
            modulesInLayer.sort(Comparator.comparing(e -> e.reference().descriptor().name()));
            for (ResolvedModule module : modulesInLayer) {
                ModuleReference moduleReference = module.reference();
                if (addedModules.add(moduleReference)) {
                    String moduleName = moduleReference.descriptor().name();
                    if (!isSystemModule(moduleName)) {
                        nonSystemModuleRefs.add(new AbstractMap.SimpleEntry<>(moduleReference, layer));
                    }
                }
            }
        }
        Set<URI> uriElements = new LinkedHashSet<>();
        for (Map.Entry<ModuleReference, ModuleLayer> e : nonSystemModuleRefs) {
            ModuleReference ref = e.getKey();
            Optional<URI> location = ref.location();
            location.ifPresent(uriElements::add);
        }
        return Collections.unmodifiableSet(uriElements);
    }

    private static void findLayerOrder(ModuleLayer layer, Set<ModuleLayer> layerVisited, Deque<ModuleLayer> layersOut) {
        if (layerVisited.add(layer)) {
            List<ModuleLayer> parents = layer.parents();
            for (ModuleLayer parent : parents) {
                findLayerOrder(parent, layerVisited, layersOut);
            }
            layersOut.push(layer);
        }
    }

    private static boolean isSystemModule(final String moduleName) {
        return moduleName.startsWith("java.")
                || moduleName.startsWith("javax.")
                || moduleName.startsWith("javafx.")
                || moduleName.startsWith("jdk.")
                || moduleName.startsWith("oracle.");
    }

    private static final class CallerResolver extends SecurityManager {
        @Override
        protected Class<?>[] getClassContext() {
            return super.getClassContext();
        }
    }
}

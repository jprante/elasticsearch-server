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

package org.elasticsearch.plugins;

import org.apache.logging.log4j.Logger;
import org.apache.lucene.analysis.util.CharFilterFactory;
import org.apache.lucene.analysis.util.TokenFilterFactory;
import org.apache.lucene.analysis.util.TokenizerFactory;
import org.apache.lucene.codecs.Codec;
import org.apache.lucene.codecs.DocValuesFormat;
import org.apache.lucene.codecs.PostingsFormat;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.Version;
import org.elasticsearch.action.admin.cluster.node.info.PluginsAndModules;
import org.elasticsearch.bootstrap.JarHell;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.component.AbstractComponent;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.io.FileSystemUtils;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.threadpool.ExecutorBuilder;
import org.elasticsearch.transport.TcpTransport;

import java.io.IOException;
import java.lang.module.Configuration;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReference;
import java.lang.reflect.Constructor;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.elasticsearch.common.io.FileSystemUtils.isAccessibleDirectory;

public class PluginsService extends AbstractComponent {

    private final Path configPath;

    /**
     * We keep around a list of plugins and modules
     */
    private final List<Tuple<PluginInfo, Plugin>> plugins;
    private final PluginsAndModules info;
    public static final Setting<List<String>> MANDATORY_SETTING =
        Setting.listSetting("plugin.mandatory", Collections.emptyList(), Function.identity(), Property.NodeScope);

    public List<Setting<?>> getPluginSettings() {
        return plugins.stream().flatMap(p -> p.v2().getSettings().stream()).collect(Collectors.toList());
    }

    public List<String> getPluginSettingsFilter() {
        return plugins.stream().flatMap(p -> p.v2().getSettingsFilter().stream()).collect(Collectors.toList());
    }

    /**
     * Constructs a new PluginService
     * @param settings The settings of the system
     * @param modulesDirectory The directory modules exist in, or null if modules should not be loaded from the filesystem
     * @param pluginsDirectory The directory plugins exist in, or null if plugins should not be loaded from the filesystem
     * @param classpathPlugins Plugins that exist in the classpath which should be loaded
     */
    public PluginsService(Settings settings, Path configPath, Path modulesDirectory, Path pluginsDirectory,
                          Collection<Class<? extends Plugin>> classpathPlugins) {
        super(settings);

        this.configPath = configPath;

        List<Tuple<PluginInfo, Plugin>> pluginsLoaded = new ArrayList<>();
        List<PluginInfo> pluginsList = new ArrayList<>();
        // we need to build a List of plugins for checking mandatory plugins
        final List<String> pluginsNames = new ArrayList<>();
        // first we load plugins that are on the classpath. this is for tests and transport clients
        for (Class<? extends Plugin> pluginClass : classpathPlugins) {
            Plugin plugin = loadPlugin(pluginClass, settings, configPath);
            PluginInfo pluginInfo = new PluginInfo(pluginClass.getName(), "classpath plugin", "NA", Version.CURRENT, "1.8",
                                                   pluginClass.getName(), Collections.emptyList(), false);
            if (logger.isTraceEnabled()) {
                logger.trace("plugin loaded from classpath [{}]", pluginInfo);
            }
            pluginsLoaded.add(new Tuple<>(pluginInfo, plugin));
            pluginsList.add(pluginInfo);
            pluginsNames.add(pluginInfo.getName());
        }

        Set<Bundle> seenBundles = new LinkedHashSet<>();
        List<PluginInfo> modulesList = new ArrayList<>();
        // load modules
        if (modulesDirectory != null) {
            try {
                Set<Bundle> modules = getModuleBundles(modulesDirectory);
                for (Bundle bundle : modules) {
                    modulesList.add(bundle.plugin);
                }
                seenBundles.addAll(modules);
            } catch (IOException ex) {
                throw new IllegalStateException("Unable to initialize modules", ex);
            }
        }

        // now, find all the ones that are in plugins/
        if (pluginsDirectory != null) {
            try {
                // TODO: remove this leniency, but tests bogusly rely on it
                if (isAccessibleDirectory(pluginsDirectory, logger)) {
                    checkForFailedPluginRemovals(pluginsDirectory);
                    // call findBundles directly to get the meta plugin names
                    List<BundleCollection> plugins = findBundles(pluginsDirectory, "plugin");
                    for (final BundleCollection plugin : plugins) {
                        final Collection<Bundle> bundles = plugin.bundles();
                        for (final Bundle bundle : bundles) {
                            pluginsList.add(bundle.plugin);
                        }
                        seenBundles.addAll(bundles);
                        pluginsNames.add(plugin.name());
                    }
                }
            } catch (IOException ex) {
                throw new IllegalStateException("Unable to initialize plugins", ex);
            }
        }

        List<Tuple<PluginInfo, Plugin>> loaded = loadBundles(seenBundles);
        pluginsLoaded.addAll(loaded);

        this.info = new PluginsAndModules(pluginsList, modulesList);
        this.plugins = Collections.unmodifiableList(pluginsLoaded);

        // Checking expected plugins
        List<String> mandatoryPlugins = MANDATORY_SETTING.get(settings);
        if (mandatoryPlugins.isEmpty() == false) {
            Set<String> missingPlugins = new HashSet<>();
            for (String mandatoryPlugin : mandatoryPlugins) {
                if (!pluginsNames.contains(mandatoryPlugin)) {
                    missingPlugins.add(mandatoryPlugin);
                }
            }
            if (!missingPlugins.isEmpty()) {
                final String message = String.format(
                        Locale.ROOT,
                        "missing mandatory plugins [%s], found plugins [%s]",
                        Strings.collectionToDelimitedString(missingPlugins, ", "),
                        Strings.collectionToDelimitedString(pluginsNames, ", "));
                throw new IllegalStateException(message);
            }
        }

        // we don't log jars in lib/ we really shouldn't log modules,
        // but for now: just be transparent so we can debug any potential issues
        logPluginInfo(info.getModuleInfos(), "module", logger);
        logPluginInfo(info.getPluginInfos(), "plugin", logger);
    }

    private static void logPluginInfo(final List<PluginInfo> pluginInfos, final String type, final Logger logger) {
        assert pluginInfos != null;
        if (pluginInfos.isEmpty()) {
            logger.info("no " + type + "s loaded");
        } else {
            for (final String name : pluginInfos.stream().map(PluginInfo::getName).sorted().collect(Collectors.toList())) {
                logger.info("loaded " + type + " [" + name + "]");
            }
        }
    }

    public Settings updatedSettings() {
        Map<String, String> foundSettings = new HashMap<>();
        final Map<String, String> features = new TreeMap<>();
        final Settings.Builder builder = Settings.builder();
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            Settings settings = plugin.v2().additionalSettings();
            for (String setting : settings.keySet()) {
                String oldPlugin = foundSettings.put(setting, plugin.v1().getName());
                if (oldPlugin != null) {
                    throw new IllegalArgumentException("Cannot have additional setting [" + setting + "] " +
                        "in plugin [" + plugin.v1().getName() + "], already added in plugin [" + oldPlugin + "]");
                }
            }
            builder.put(settings);
            final Optional<String> maybeFeature = plugin.v2().getFeature();
            if (maybeFeature.isPresent()) {
                final String feature = maybeFeature.get();
                if (features.containsKey(feature)) {
                    final String message = String.format(
                            Locale.ROOT,
                            "duplicate feature [%s] in plugin [%s], already added in [%s]",
                            feature,
                            plugin.v1().getName(),
                            features.get(feature));
                    throw new IllegalArgumentException(message);
                }
                features.put(feature, plugin.v1().getName());
            }
        }
        for (final String feature : features.keySet()) {
            builder.put(TcpTransport.FEATURE_PREFIX + "." + feature, true);
        }
        return builder.put(this.settings).build();
    }

    public Collection<org.elasticsearch.common.inject.Module> createGuiceModules() {
        List<org.elasticsearch.common.inject.Module> modules = new ArrayList<>();
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            modules.addAll(plugin.v2().createGuiceModules());
        }
        return modules;
    }

    public List<ExecutorBuilder<?>> getExecutorBuilders(Settings settings) {
        final ArrayList<ExecutorBuilder<?>> builders = new ArrayList<>();
        for (final Tuple<PluginInfo, Plugin> plugin : plugins) {
            builders.addAll(plugin.v2().getExecutorBuilders(settings));
        }
        return builders;
    }

    /** Returns all classes injected into guice by plugins which extend {@link LifecycleComponent}. */
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        List<Class<? extends LifecycleComponent>> services = new ArrayList<>();
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            services.addAll(plugin.v2().getGuiceServiceClasses());
        }
        return services;
    }

    public void onIndexModule(IndexModule indexModule) {
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            plugin.v2().onIndexModule(indexModule);
        }
    }

    /**
     * Get information about plugins and modules
     */
    public PluginsAndModules info() {
        return info;
    }

    /**
     * An abstraction over a single plugin and meta-plugins.
     */
    interface BundleCollection {
        String name();
        Collection<Bundle> bundles();
    }

    // a "bundle" is a group of plugins in a single classloader
    // really should be 1-1, but we are not so fortunate
    public static class Bundle implements BundleCollection {
        final PluginInfo plugin;
        final Set<URI> uris;

        public Bundle(PluginInfo plugin, Path dir) throws IOException {
            this.plugin = Objects.requireNonNull(plugin);
            Set<URI> uris = new LinkedHashSet<>();
            // gather urls for jar files
            try (DirectoryStream<Path> jarStream = Files.newDirectoryStream(dir, "*.jar")) {
                for (Path jar : jarStream) {
                    // normalize with toRealPath to get symlinks out of our hair
                    URI uri = jar.toRealPath().toUri();
                    if (uris.add(uri) == false) {
                        throw new IllegalStateException("duplicate codebase: " + uri);
                    }
                }
            }
            this.uris = Objects.requireNonNull(uris);
        }

        @Override
        public String name() {
            return plugin.getName();
        }

        @Override
        public Collection<Bundle> bundles() {
            return Collections.singletonList(this);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Bundle bundle = (Bundle) o;
            return Objects.equals(plugin, bundle.plugin);
        }

        @Override
        public int hashCode() {
            return Objects.hash(plugin);
        }
    }

    /**
     * Represents a meta-plugin and the {@link Bundle}s corresponding to its constituents.
     */
    static class MetaBundle implements BundleCollection {
        private final String name;
        private final List<Bundle> bundles;

        MetaBundle(final String name, final List<Bundle> bundles) {
            this.name = name;
            this.bundles = bundles;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public Collection<Bundle> bundles() {
            return bundles;
        }
        
    }

    /**
     * Extracts all installed plugin directories from the provided {@code rootPath} expanding meta-plugins if needed.
     *
     * @param rootPath the path where the plugins are installed
     * @return a list of all plugin paths installed in the {@code rootPath}
     * @throws IOException if an I/O exception occurred reading the directories
     */
    public static List<Path> findPluginDirs(final Path rootPath) throws IOException {
        final Tuple<List<Path>, Map<String, List<Path>>> groupedPluginDirs = findGroupedPluginDirs(rootPath);
        return Stream.concat(
                groupedPluginDirs.v1().stream(),
                groupedPluginDirs.v2().values().stream().flatMap(Collection::stream))
                .collect(Collectors.toList());
    }

    /**
     * Extracts all installed plugin directories from the provided {@code rootPath} expanding meta-plugins if needed. The plugins are
     * grouped into plugins and meta-plugins. The meta-plugins are keyed by the meta-plugin name.
     *
     * @param rootPath the path where the plugins are installed
     * @return a tuple of plugins as the first component and meta-plugins keyed by meta-plugin name as the second component
     * @throws IOException if an I/O exception occurred reading the directories
     */
    private static Tuple<List<Path>, Map<String, List<Path>>> findGroupedPluginDirs(final Path rootPath) throws IOException {
        final List<Path> plugins = new ArrayList<>();
        final Map<String, List<Path>> metaPlugins = new LinkedHashMap<>();
        final Set<String> seen = new HashSet<>();
        if (Files.exists(rootPath)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(rootPath)) {
                for (Path plugin : stream) {
                    if (FileSystemUtils.isDesktopServicesStore(plugin) ||
                            plugin.getFileName().toString().startsWith(".removing-")) {
                        continue;
                    }
                    if (seen.add(plugin.getFileName().toString()) == false) {
                        throw new IllegalStateException("duplicate plugin: " + plugin);
                    }
                    if (MetaPluginInfo.isMetaPlugin(plugin)) {
                        final String name = plugin.getFileName().toString();
                        try (DirectoryStream<Path> subStream = Files.newDirectoryStream(plugin)) {
                            for (Path subPlugin : subStream) {
                                if (MetaPluginInfo.isPropertiesFile(subPlugin) ||
                                        FileSystemUtils.isDesktopServicesStore(subPlugin)) {
                                    continue;
                                }
                                if (seen.add(subPlugin.getFileName().toString()) == false) {
                                    throw new IllegalStateException("duplicate plugin: " + subPlugin);
                                }
                                metaPlugins.computeIfAbsent(name, n -> new ArrayList<>()).add(subPlugin);
                            }
                        }
                    } else {
                        plugins.add(plugin);
                    }
                }
            }
        }
        return Tuple.tuple(plugins, metaPlugins);
    }

    /**
     * Verify the given plugin is compatible with the current Elasticsearch installation.
     */
    public static void verifyCompatibility(PluginInfo info) {
        if (info.getElasticsearchVersion().equals(Version.CURRENT) == false) {
            throw new IllegalArgumentException("Plugin [" + info.getName() + "] was built for Elasticsearch version "
                + info.getElasticsearchVersion() + " but version " + Version.CURRENT + " is running");
        }
        JarHell.checkJavaVersion(info.getName(), info.getJavaVersion());
    }

    public static void checkForFailedPluginRemovals(final Path pluginsDirectory) throws IOException {
        /*
         * Check for the existence of a marker file that indicates any plugins are in a garbage state from a failed attempt to remove the
         * plugin.
         */
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(pluginsDirectory, ".removing-*")) {
            final Iterator<Path> iterator = stream.iterator();
            if (iterator.hasNext()) {
                final Path removing = iterator.next();
                final String fileName = removing.getFileName().toString();
                final String name = fileName.substring(1 + fileName.indexOf("-"));
                final String message = String.format(
                        Locale.ROOT,
                        "found file [%s] from a failed attempt to remove the plugin [%s]; execute [elasticsearch-plugin remove %2$s]",
                        removing,
                        name);
                throw new IllegalStateException(message);
            }
        }
    }

    /** Get bundles for plugins installed in the given modules directory. */
    public static Set<Bundle> getModuleBundles(Path modulesDirectory) throws IOException {
        return findBundles(modulesDirectory, "module").stream().flatMap(b -> b.bundles().stream()).collect(Collectors.toSet());
    }

    /** Get bundles for plugins installed in the given plugins directory. */
    public static Set<Bundle> getPluginBundles(final Path pluginsDirectory) throws IOException {
        return findBundles(pluginsDirectory, "plugin").stream().flatMap(b -> b.bundles().stream()).collect(Collectors.toSet());
    }

    // searches subdirectories under the given directory for plugin directories
    private static List<BundleCollection> findBundles(final Path directory, String type) throws IOException {
        final List<BundleCollection> bundles = new ArrayList<>();
        final Set<Bundle> seenBundles = new HashSet<>();
        final Tuple<List<Path>, Map<String, List<Path>>> groupedPluginDirs = findGroupedPluginDirs(directory);
        for (final Path plugin : groupedPluginDirs.v1()) {
            final Bundle bundle = readPluginBundle(seenBundles, plugin, type);
            bundles.add(bundle);
        }
        for (final Map.Entry<String, List<Path>> metaPlugin : groupedPluginDirs.v2().entrySet()) {
            final List<Bundle> metaPluginBundles = new ArrayList<>();
            for (final Path metaPluginPlugin : metaPlugin.getValue()) {
                final Bundle bundle = readPluginBundle(seenBundles, metaPluginPlugin, type);
                metaPluginBundles.add(bundle);
            }
            final MetaBundle metaBundle = new MetaBundle(metaPlugin.getKey(), metaPluginBundles);
            bundles.add(metaBundle);
        }

        return bundles;
    }

    // get a bundle for a single plugin dir
    private static Bundle readPluginBundle(final Set<Bundle> bundles, final Path plugin, String type) throws IOException {
        Loggers.getLogger(PluginsService.class).trace("--- adding [{}] [{}]", type, plugin.toAbsolutePath());
        final PluginInfo info;
        try {
            info = PluginInfo.readFromProperties(plugin);
        } catch (final IOException e) {
            throw new IllegalStateException("Could not load plugin descriptor for " + type +
                                            " directory [" + plugin.getFileName() + "]", e);
        }
        final Bundle bundle = new Bundle(info, plugin);
        if (bundles.add(bundle) == false) {
            throw new IllegalStateException("duplicate " + type + ": " + info);
        }
        return bundle;
    }

    /**
     * Return the given bundles, sorted in dependency loading order.
     *
     * This sort is stable, so that if two plugins do not have any interdependency,
     * their relative order from iteration of the provided set will not change.
     *
     * @throws IllegalStateException if a dependency cycle is found
     */
    public static List<Bundle> sortBundles(Set<Bundle> bundles) {
        Map<String, Bundle> namedBundles = bundles.stream().collect(Collectors.toMap(b -> b.plugin.getName(), Function.identity()));
        LinkedHashSet<Bundle> sortedBundles = new LinkedHashSet<>();
        LinkedHashSet<String> dependencyStack = new LinkedHashSet<>();
        for (Bundle bundle : bundles) {
            addSortedBundle(bundle, namedBundles, sortedBundles, dependencyStack);
        }
        return new ArrayList<>(sortedBundles);
    }

    // add the given bundle to the sorted bundles, first adding dependencies
    private static void addSortedBundle(Bundle bundle, Map<String, Bundle> bundles, LinkedHashSet<Bundle> sortedBundles,
                                        LinkedHashSet<String> dependencyStack) {

        String name = bundle.plugin.getName();
        if (dependencyStack.contains(name)) {
            StringBuilder msg = new StringBuilder("Cycle found in plugin dependencies: ");
            dependencyStack.forEach(s -> {
                msg.append(s);
                msg.append(" -> ");
            });
            msg.append(name);
            throw new IllegalStateException(msg.toString());
        }
        if (sortedBundles.contains(bundle)) {
            // already added this plugin, via a dependency
            return;
        }

        dependencyStack.add(name);
        for (String dependency : bundle.plugin.getExtendedPlugins()) {
            Bundle depBundle = bundles.get(dependency);
            if (depBundle == null) {
                throw new IllegalArgumentException("Missing plugin [" + dependency + "], dependency of [" + name + "]");
            }
            addSortedBundle(depBundle, bundles, sortedBundles, dependencyStack);
            assert sortedBundles.contains(depBundle);
        }
        dependencyStack.remove(name);

        sortedBundles.add(bundle);
    }

    private List<Tuple<PluginInfo,Plugin>> loadBundles(Set<Bundle> bundles) {
        List<Tuple<PluginInfo, Plugin>> plugins = new ArrayList<>();
        Map<String, Set<URI>> transitiveUris = new HashMap<>();
        List<Bundle> sortedBundles = sortBundles(bundles);
        Map<String, Plugin> loadedPlugins = new HashMap<>();
        Map<String, Bundle> loadedBundles = new HashMap<>();
        for (Bundle bundle : sortedBundles) {
            checkBundleJarHell(bundle, transitiveUris);
            final Plugin plugin = loadBundle(bundle, loadedPlugins, loadedBundles);
            plugins.add(new Tuple<>(bundle.plugin, plugin));
        }

        return Collections.unmodifiableList(plugins);
    }

    // jar-hell check the bundle against the parent classloader and extended plugins
    // the plugin cli does it, but we do it again, in case lusers mess with jar files manually
    public static void checkBundleJarHell(Bundle bundle, Map<String, Set<URI>> transitiveUris) {
        // invariant: any plugins this plugin bundle extends have already been added to transitiveUrls
        List<String> exts = bundle.plugin.getExtendedPlugins();

        try {
            final Logger logger = ESLoggerFactory.getLogger(JarHell.class);
            Set<URI> uris = new HashSet<>();
            for (String extendedPlugin : exts) {
                Set<URI> pluginUris = transitiveUris.get(extendedPlugin);
                assert pluginUris != null : "transitive urls should have already been set for " + extendedPlugin;

                Set<URI> intersection = new HashSet<>(uris);
                intersection.retainAll(pluginUris);
                if (intersection.isEmpty() == false) {
                    throw new IllegalStateException("jar hell! extended plugins " + exts +
                                                    " have duplicate codebases with each other: " + intersection);
                }

                intersection = new HashSet<>();
                for (URI uri : bundle.uris) {
                    intersection.add(uri);
                }
                intersection.retainAll(pluginUris);
                if (intersection.isEmpty() == false) {
                    throw new IllegalStateException("jar hell! duplicate codebases with extended plugin [" +
                                                    extendedPlugin + "]: " + intersection);
                }

                uris.addAll(pluginUris);
                JarHell.checkJarHell(uris, logger::debug); // check jarhell as we add each extended plugin's urls
            }

            for (URI uri : bundle.uris) {
                uris.add(uri);
            }
            JarHell.checkJarHell(uris, logger::debug); // check jarhell of each extended plugin against this plugin
            transitiveUris.put(bundle.plugin.getName(), uris);

            Set<URI> classpath = JarHell.parseClassPath();
            // check we don't have conflicting codebases with core
            Set<URI> intersection = new HashSet<>(classpath);
            intersection.retainAll(bundle.uris);
            if (intersection.isEmpty() == false) {
                throw new IllegalStateException("jar hell! duplicate codebases between plugin and core: " + intersection);
            }
            // check we don't have conflicting classes
            Set<URI> union = new HashSet<>(classpath);
            for (URI uri : bundle.uris) {
                union.add(uri);
            }
            JarHell.checkJarHell(union, logger::debug);
        } catch (Exception e) {
            throw new IllegalStateException("failed to load plugin " + bundle.plugin.getName() + " due to jar hell", e);
        }
    }

    private Plugin loadBundle(Bundle bundle, Map<String, Plugin> loadedPlugins, Map<String, Bundle> loadedBundles) {
        String name = bundle.plugin.getName();
        verifyCompatibility(bundle.plugin);
        List<URI> uris = new ArrayList<>(bundle.uris);
        for (String extendedPluginName : bundle.plugin.getExtendedPlugins()) {
            Plugin extendedPlugin = loadedPlugins.get(extendedPluginName);
            if (ExtensiblePlugin.class.isInstance(extendedPlugin) == false) {
                throw new IllegalStateException("Plugin [" + name + "] cannot extend non-extensible plugin [" + extendedPluginName + "]");
            }
            Bundle extendedPluginBundle = loadedBundles.get(extendedPluginName);
            uris.addAll(extendedPluginBundle.uris);
        }

        // create a child to load the plugin in this bundle
        //ClassLoader parentLoader = PluginLoaderIndirection.createLoader(getClass().getClassLoader(), extendedLoaders);
        //ClassLoader loader = URLClassLoader.newInstance(bundle.urls.toArray(new URL[0]), parentLoader);
        ClassLoader loader = createClassLoader(bundle.plugin.getModulename(), uris);

        // reload SPI with any new services from the plugin
        reloadLuceneSPI(loader);
        for (String extendedPluginName : bundle.plugin.getExtendedPlugins()) {
            // note: already asserted above that extended plugins are loaded and extensible
            ((ExtensiblePlugin) loadedPlugins.get(extendedPluginName)).reloadSPI(loader);
        }
        try {
            Class<? extends Plugin> pluginClass = loader.loadClass(bundle.plugin.getClassname()).asSubclass(Plugin.class);
            Plugin plugin = loadPlugin(pluginClass, settings, configPath);
            loadedBundles.put(name, bundle);
            loadedPlugins.put(name, plugin);
            return plugin;
        } catch (ClassNotFoundException e) {
            throw new ElasticsearchException("Could not find plugin class [" + bundle.plugin.getClassname() + "]", e);
        }
    }

    private ClassLoader createClassLoader(String name, Collection<URI> uris) {
        Path[] entries = uris.stream().map(Paths::get).toArray(Path[]::new);
        ModuleFinder moduleFinder = ModuleFinder.of(entries);
        Set<ModuleReference> moduleReferences = moduleFinder.findAll();
        Set<String> moduleNames = moduleReferences.stream()
                .map(ref -> ref.descriptor().name())
                .collect(Collectors.toSet());
        logger.info("plugin module name = {} uris = {} module names = {}", name, uris, moduleNames);
        if (moduleNames.isEmpty()) {
            throw new IllegalArgumentException("no module found in " + uris); // no module found, no classloader
        }
        if (!moduleNames.contains(name)) {
            throw new IllegalArgumentException("module name " + name + " not found in " + moduleNames); // no module found, no classloader
        }
        ModuleLayer boot = ModuleLayer.boot();
        Configuration configuration = boot.configuration().resolve(moduleFinder, ModuleFinder.of(), moduleNames);
        ModuleLayer moduleLayer = boot.defineModulesWithOneLoader(configuration, getClass().getClassLoader());
        //ModuleLayer.Controller controller =
        //        ModuleLayer.defineModulesWithOneLoader(configuration, List.of(boot), getClass().getClassLoader());
        return moduleLayer.findLoader(name);
    }

    /**
     * Reloads all Lucene SPI implementations using the new classloader.
     * This method must be called after the new classloader has been created to
     * register the services for use.
     */
    private static void reloadLuceneSPI(ClassLoader loader) {
        // do NOT change the order of these method calls!

        // Codecs:
        PostingsFormat.reloadPostingsFormats(loader);
        DocValuesFormat.reloadDocValuesFormats(loader);
        Codec.reloadCodecs(loader);
        // Analysis:
        CharFilterFactory.reloadCharFilters(loader);
        TokenFilterFactory.reloadTokenFilters(loader);
        TokenizerFactory.reloadTokenizers(loader);
    }

    private Plugin loadPlugin(Class<? extends Plugin> pluginClass, Settings settings, Path configPath) {
        final Constructor<?>[] constructors = pluginClass.getConstructors();
        if (constructors.length == 0) {
            throw new IllegalStateException("no public constructor for [" + pluginClass.getName() + "]");
        }

        if (constructors.length > 1) {
            throw new IllegalStateException("no unique public constructor for [" + pluginClass.getName() + "]");
        }

        final Constructor<?> constructor = constructors[0];
        if (constructor.getParameterCount() > 2) {
            throw new IllegalStateException(signatureMessage(pluginClass));
        }

        final Class[] parameterTypes = constructor.getParameterTypes();
        try {
            if (constructor.getParameterCount() == 2 && parameterTypes[0] == Settings.class && parameterTypes[1] == Path.class) {
                return (Plugin)constructor.newInstance(settings, configPath);
            } else if (constructor.getParameterCount() == 1 && parameterTypes[0] == Settings.class) {
                return (Plugin)constructor.newInstance(settings);
            } else if (constructor.getParameterCount() == 0) {
                return (Plugin)constructor.newInstance();
            } else {
                throw new IllegalStateException(signatureMessage(pluginClass));
            }
        } catch (final ReflectiveOperationException e) {
            throw new IllegalStateException("failed to load plugin class [" + pluginClass.getName() + "]", e);
        }
    }

    private String signatureMessage(final Class<? extends Plugin> clazz) {
        return String.format(
                Locale.ROOT,
                "no public constructor of correct signature for [%s]; must be [%s], [%s], or [%s]",
                clazz.getName(),
                "(org.elasticsearch.common.settings.Settings,java.nio.file.Path)",
                "(org.elasticsearch.common.settings.Settings)",
                "()");
    }

    public <T> List<T> filterPlugins(Class<T> type) {
        return plugins.stream().filter(x -> type.isAssignableFrom(x.v2().getClass()))
            .map(p -> ((T)p.v2())).collect(Collectors.toList());
    }
}

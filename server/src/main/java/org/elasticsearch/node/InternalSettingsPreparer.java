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

package org.elasticsearch.node;

import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.elasticsearch.Version;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.io.PathUtils;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsException;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.env.Environment;

public class InternalSettingsPreparer {

    public static final String SECRET_PROMPT_VALUE = "${prompt.secret}";
    public static final String TEXT_PROMPT_VALUE = "${prompt.text}";

    /**
     * Prepares the settings by gathering all elasticsearch system properties and setting defaults.
     */
    public static Settings prepareSettings(Settings input) {
        Settings.Builder output = Settings.builder();
        initializeSettings(output, input, Collections.emptyMap());
        finalizeSettings(output, null);
        return output.build();
    }

    /**
     * Prepares the settings by gathering all elasticsearch system properties, optionally loading the configuration settings,
     * and then replacing all property placeholders. If a {@link Terminal} is provided and configuration settings are loaded,
     * settings with a value of <code>${prompt.text}</code> or <code>${prompt.secret}</code> will result in a prompt for
     * the setting to the user.
     * @param input The custom settings to use. These are not overwritten by settings in the configuration file.
     * @param terminal the Terminal to use for input/output
     * @return the {@link Settings} and {@link Environment} as a {@link Tuple}
     */
    public static Environment prepareEnvironment(Settings input, Terminal terminal) {
        return prepareEnvironment(input, terminal, Collections.emptyMap(), null);
    }

    /**
     * Prepares the settings by gathering all elasticsearch system properties, optionally loading the configuration settings,
     * and then replacing all property placeholders. If a {@link Terminal} is provided and configuration settings are loaded,
     * settings with a value of <code>${prompt.text}</code> or <code>${prompt.secret}</code> will result in a prompt for
     * the setting to the user.
     *
     * @param input      the custom settings to use; these are not overwritten by settings in the configuration file
     * @param terminal   the Terminal to use for input/output
     * @param properties map of properties key/value pairs (usually from the command-line)
     * @param configPath path to config directory; (use null to indicate the default)
     * @return the {@link Settings} and {@link Environment} as a {@link Tuple}
     */
    public static Environment prepareEnvironment(Settings input, Terminal terminal, Map<String, String> properties, Path configPath) {
        // just create enough settings to build the environment, to get the config dir
        Settings.Builder output = Settings.builder();
        initializeSettings(output, input, properties);
        Environment environment = new Environment(output.build(), configPath);

        Settings.Builder builder = Settings.builder(); // start with a fresh output

        // we accept multiple config files of the pattern "elasticsearch*config.json or .yml or. yaml
        List<Path> configFilePaths = new ArrayList<>();
        try {
            final Set<FileVisitOption> options = EnumSet.of(FileVisitOption.FOLLOW_LINKS);
            PathMatcher pathMatcher = PathUtils.getDefaultFileSystem()
                    .getPathMatcher("glob:**/elasticsearch.{json,yml,yaml}");
            Files.walkFileTree(environment.configFile(), options, 2, new SimpleFileVisitor<Path>() {

                @Override
                public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) {
                    if (pathMatcher.matches(path)) {
                        configFilePaths.add(path);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            throw new SettingsException("problems while finding elasticsearch config file", e);
        }
        // last, the original Elasticsearch config file
        configFilePaths.add(environment.configFile().resolve("elasticsearch.yml"));

        for (Path path : configFilePaths) {
            if (Files.exists(path)) {
                try {
                    builder.loadFromPath(path);
                } catch (IOException e) {
                    throw new SettingsException("Failed to load settings from " + path.toString(), e);
                }
                // only one config file
                break;
            }
        }

        // re-initialize settings now that the config file(s) has been loaded
        initializeSettings(builder, input, properties);
        finalizeSettings(builder, terminal);

        environment = new Environment(builder.build(), configPath);

        // we put back the path.logs so we can use it in the logging configuration file
        builder.put(Environment.PATH_LOGS_SETTING.getKey(), environment.logsFile().toAbsolutePath().normalize().toString());

        Settings settings = builder.build();
        try {
            XContentBuilder xContentBuilder = JsonXContent.contentBuilder();
            settings.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
            LogManager.getLogger("internal").info("settings = " + Strings.toString(xContentBuilder));
        } catch (IOException e) {
            // ignore
        }

        return new Environment(settings, configPath);
    }

    /**
     * Initializes the builder with the given input settings, and applies settings from the specified map (these settings typically come
     * from the command line).
     *
     * @param output the settings builder to apply the input and default settings to
     * @param input the input settings
     * @param esSettings a map from which to apply settings
     */
    static void initializeSettings(final Settings.Builder output, final Settings input, final Map<String, String> esSettings) {
        output.put(input);
        output.putProperties(esSettings, Function.identity());
        output.replacePropertyPlaceholders();
    }

    /**
     * Finish preparing settings by replacing forced settings, prompts, and any defaults that need to be added.
     * The provided terminal is used to prompt for settings needing to be replaced.
     */
    private static void finalizeSettings(Settings.Builder output, Terminal terminal) {
        // allow to force set properties based on configuration of the settings provided
        List<String> forcedSettings = new ArrayList<>();
        for (String setting : output.keys()) {
            if (setting.startsWith("force.")) {
                forcedSettings.add(setting);
            }
        }
        for (String forcedSetting : forcedSettings) {
            String value = output.remove(forcedSetting);
            output.put(forcedSetting.substring("force.".length()), value);
        }
        output.replacePropertyPlaceholders();

        // put the cluster name
        if (output.get(ClusterName.CLUSTER_NAME_SETTING.getKey()) == null) {
            output.put(ClusterName.CLUSTER_NAME_SETTING.getKey(), ClusterName.CLUSTER_NAME_SETTING.getDefault(Settings.EMPTY).value());
        }

        replacePromptPlaceholders(output, terminal);
    }

    private static void replacePromptPlaceholders(Settings.Builder settings, Terminal terminal) {
        List<String> secretToPrompt = new ArrayList<>();
        List<String> textToPrompt = new ArrayList<>();
        for (String key : settings.keys()) {
            switch (settings.get(key)) {
                case SECRET_PROMPT_VALUE:
                    secretToPrompt.add(key);
                    break;
                case TEXT_PROMPT_VALUE:
                    textToPrompt.add(key);
                    break;
            }
        }
        for (String setting : secretToPrompt) {
            String secretValue = promptForValue(setting, terminal, true);
            if (Strings.hasLength(secretValue)) {
                settings.put(setting, secretValue);
            } else {
                // TODO: why do we remove settings if prompt returns empty??
                settings.remove(setting);
            }
        }
        for (String setting : textToPrompt) {
            String textValue = promptForValue(setting, terminal, false);
            if (Strings.hasLength(textValue)) {
                settings.put(setting, textValue);
            } else {
                // TODO: why do we remove settings if prompt returns empty??
                settings.remove(setting);
            }
        }
    }

    private static String promptForValue(String key, Terminal terminal, boolean secret) {
        if (terminal == null) {
            throw new UnsupportedOperationException("found property [" + key + "] with value ["
                + (secret ? SECRET_PROMPT_VALUE : TEXT_PROMPT_VALUE)
                + "]. prompting for property values is only supported when running elasticsearch in the foreground");
        }

        terminal.println(Terminal.Verbosity.SILENT,
            "Prompting for property values is deprecated since " + Version.V_6_3_0
                + ". Some setting values can be stored in the keystore. Consult the docs for more information.");

        if (secret) {
            return new String(terminal.readSecret("Enter value for [" + key + "]: "));
        }
        return terminal.readText("Enter value for [" + key + "]: ");
    }
}

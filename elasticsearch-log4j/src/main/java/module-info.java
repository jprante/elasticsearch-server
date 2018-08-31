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

module org.xbib.elasticsearch.log4j {

    exports org.apache.logging.log4j;
    exports org.apache.logging.log4j.message;
    exports org.apache.logging.log4j.simple;
    exports org.apache.logging.log4j.spi;
    exports org.apache.logging.log4j.status;
    exports org.apache.logging.log4j.util;

    exports org.apache.logging.log4j.core;
    exports org.apache.logging.log4j.core.appender;
    exports org.apache.logging.log4j.core.config;
    exports org.apache.logging.log4j.core.config.builder.api;
    exports org.apache.logging.log4j.core.config.builder.impl;
    exports org.apache.logging.log4j.core.config.composite;
    exports org.apache.logging.log4j.core.config.json;
    exports org.apache.logging.log4j.core.config.properties;
    exports org.apache.logging.log4j.core.config.yaml;
    exports org.apache.logging.log4j.core.filter;

    exports org.apache.log4j;
    exports org.apache.log4j.config;
    exports org.apache.log4j.helpers;
    exports org.apache.log4j.layout;
    exports org.apache.log4j.pattern;
    exports org.apache.log4j.spi;

    provides javax.annotation.processing.Processor with
            org.apache.logging.log4j.core.config.plugins.processor.PluginProcessor;

    provides org.apache.logging.log4j.spi.Provider with
            org.apache.logging.log4j.core.impl.Log4jProvider;

    provides org.apache.logging.log4j.util.PropertySource with
            org.apache.logging.log4j.util.EnvironmentPropertySource,
            org.apache.logging.log4j.util.SystemPropertiesPropertySource;

    uses javax.annotation.processing.Processor;
    uses org.apache.logging.log4j.spi.Provider;
    uses org.apache.logging.log4j.util.PropertySource;

    requires org.xbib.elasticsearch.jackson;

    requires java.compiler; // javax.annotation.processing
    requires java.desktop; // java.beans
    requires java.rmi;
    requires java.sql;
    requires java.management; // javax.management
    requires java.naming;
    requires jdk.scripting.nashorn; // javax.script

    // external modules we do not include
    requires static java.annotation;
    requires static javax.jms.api;
    requires static org.codehaus.stax2; // StAX2 in JacksonFactory
    requires static disruptor;
    requires static org.apache.commons.compress;
    requires static commons.csv;
    requires static jeromq;
    requires static jctools.core;
    requires static org.osgi.core;
    requires static jansi;

    // remove all mail and activation deps because of forbidden com.sun packages
    // kafka requires jackson but can not access our jackson module, so drop it
}
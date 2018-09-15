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
    exports org.apache.logging.log4j.core;
    exports org.apache.logging.log4j.core.appender;
    exports org.apache.logging.log4j.core.config;
    exports org.apache.logging.log4j.core.config.builder.api;
    exports org.apache.logging.log4j.core.config.builder.impl;
    exports org.apache.logging.log4j.core.config.composite;
    exports org.apache.logging.log4j.core.config.json;
    exports org.apache.logging.log4j.core.config.plugins;
    exports org.apache.logging.log4j.core.config.plugins.convert;
    exports org.apache.logging.log4j.core.config.plugins.processor;
    exports org.apache.logging.log4j.core.config.plugins.util;
    exports org.apache.logging.log4j.core.config.plugins.validation;
    exports org.apache.logging.log4j.core.config.plugins.validation.constraints;
    exports org.apache.logging.log4j.core.config.plugins.validation.validators;
    exports org.apache.logging.log4j.core.config.plugins.visitors;
    exports org.apache.logging.log4j.core.config.properties;
    exports org.apache.logging.log4j.core.config.xml;
    exports org.apache.logging.log4j.core.config.yaml;
    exports org.apache.logging.log4j.core.filter;
    exports org.apache.logging.log4j.core.impl;
    exports org.apache.logging.log4j.core.jackson;
    exports org.apache.logging.log4j.core.jmx;
    exports org.apache.logging.log4j.core.layout;
    exports org.apache.logging.log4j.core.lookup;
    exports org.apache.logging.log4j.core.message;
    exports org.apache.logging.log4j.core.net;
    exports org.apache.logging.log4j.core.net.ssl;
    exports org.apache.logging.log4j.core.parser;
    exports org.apache.logging.log4j.core.pattern;
    exports org.apache.logging.log4j.core.script;
    exports org.apache.logging.log4j.core.selector;
    exports org.apache.logging.log4j.core.time;
    exports org.apache.logging.log4j.core.tools;
    exports org.apache.logging.log4j.core.tools.picocli;
    exports org.apache.logging.log4j.core.util;
    exports org.apache.logging.log4j.core.util.datetime;
    exports org.apache.logging.log4j.jul;
    exports org.apache.logging.log4j.message;
    exports org.apache.logging.log4j.simple;
    exports org.apache.logging.log4j.spi;
    exports org.apache.logging.log4j.status;
    exports org.apache.logging.log4j.util;

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
    uses org.apache.logging.log4j.message.ThreadDumpMessage.ThreadInfoFactory;

    requires org.xbib.elasticsearch.jackson;

    requires java.compiler; // javax.annotation.processing for org.apache.logging.log4j.core.config.plugins.PluginProcessor
    requires java.management; // javax.management

    // optional stuff in core
    requires static java.sql;
    requires static java.naming;
    requires static java.rmi;
    requires static java.desktop; // java.beans
    requires static jdk.scripting.nashorn; // javax.script

    // external modules
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

    // we removed all mail and activation deps because of forbidden com.sun packages
    // kafka is too complex, requires jackson but can not access our jackson module, so it's removed
}
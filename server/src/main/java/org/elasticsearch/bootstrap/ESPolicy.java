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
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLoggerFactory;

import java.net.SocketPermission;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.CodeSource;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.URIParameter;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Custom policy for union of static and dynamic permissions.
 */
public final class ESPolicy extends Policy {

    private static final Logger logger = ESLoggerFactory.getLogger(ESPolicy.class);

    /** template policy file */
    private static final String POLICY_RESOURCE = "security.policy";

    /** limited policy for scripts */
    private static final String UNTRUSTED_RESOURCE = "untrusted.policy";

    private final Policy template;

    private final Policy untrusted;

    private final Policy system;

    private final PermissionCollection dynamic;

    private final Map<URI, Policy> plugins;

    public ESPolicy(PermissionCollection dynamic, Map<URI, Policy> plugins, boolean filterBadDefaults)
            throws URISyntaxException {
        logger.info("reading policy: " + POLICY_RESOURCE);
        this.template = readPolicy(getClass().getResource(POLICY_RESOURCE).toURI());
        logger.info("reading untrusted policy: " + UNTRUSTED_RESOURCE);
        this.untrusted = readPolicy(getClass().getResource(UNTRUSTED_RESOURCE).toURI());
        if (filterBadDefaults) {
            this.system = new SystemPolicy(Policy.getPolicy());
        } else {
            this.system = Policy.getPolicy();
        }
        this.dynamic = dynamic;
        this.plugins = plugins;
    }

    /**
     * Reads and returns the specified {@code policyFile}.
     */
    @SuppressForbidden(reason = "accesses fully qualified URIs to configure security")
    public static Policy readPolicy(URI policyFile) {
        try {
            return Policy.getInstance("JavaPolicy", new URIParameter(policyFile));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("unable to parse policy file `" + policyFile + "`", e);
        }
    }

    @Override
    @SuppressForbidden(reason = "fast equals check is desired")
    public boolean implies(ProtectionDomain domain, Permission permission) {
        CodeSource codeSource = domain.getCodeSource();
        // codesource can be null when reducing privileges via doPrivileged()
        if (codeSource == null) {
            return false;
        }
        try {
            // location can be null... ??? nobody knows
            // https://bugs.openjdk.java.net/browse/JDK-8129972
            if (codeSource.getLocation() != null) {
                URI location = codeSource.getLocation().toURI();
                // run scripts with limited permissions
                if (BootstrapInfo.UNTRUSTED_CODEBASE.equals(location.getPath())) {
                    return untrusted.implies(domain, permission);
                }
                // check for an additional plugin permission
                Policy pluginPolicy = plugins.get(location);
                if (pluginPolicy != null) {
                    return pluginPolicy.implies(domain, permission) ||
                            template.implies(domain, permission) ||
                            dynamic.implies(permission) ||
                            system.implies(domain, permission);
                }
            } else {
                logger.warn("location is null for code source " + codeSource);
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("location URI fails for " + codeSource);
        }
        return template.implies(domain, permission) ||
                dynamic.implies(permission) ||
                system.implies(domain, permission);
    }

    /**
     * Classy puzzler to rethrow any checked exception as an unchecked one.
     */
    private static class Rethrower<T extends Throwable> {
        private void rethrow(Throwable t) throws T {
            throw (T) t;
        }
    }

    @Override
    public PermissionCollection getPermissions(CodeSource codesource) {
        // code should not rely on this method, or at least use it correctly:
        // https://bugs.openjdk.java.net/browse/JDK-8014008
        // return them a new empty permissions object so jvisualvm etc work
        for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
            if ("sun.rmi.server.LoaderHandler".equals(element.getClassName()) &&
                    "loadClass".equals(element.getMethodName())) {
                return new Permissions();
            }
        }
        // return UNSUPPORTED_EMPTY_COLLECTION since it is safe.
        return super.getPermissions(codesource);
    }

    // TODO: remove this hack when insecure defaults are removed from java

    /**
     * Wraps a bad default permission, applying a pre-implies to any permissions before checking if the wrapped bad default permission
     * implies a permission.
     */
    private static class BadDefaultPermission extends Permission {

        private final Permission badDefaultPermission;
        private final Predicate<Permission> preImplies;

        /**
         * Construct an instance with a pre-implies check to apply to desired permissions.
         *
         * @param badDefaultPermission the bad default permission to wrap
         * @param preImplies           a test that is applied to a desired permission before checking if the bad default permission that
         *                             this instance wraps implies the desired permission
         */
        BadDefaultPermission(final Permission badDefaultPermission, final Predicate<Permission> preImplies) {
            super(badDefaultPermission.getName());
            this.badDefaultPermission = badDefaultPermission;
            this.preImplies = preImplies;
        }

        @Override
        public final boolean implies(Permission permission) {
            return preImplies.test(permission) && badDefaultPermission.implies(permission);
        }

        @Override
        public final boolean equals(Object obj) {
            return badDefaultPermission.equals(obj);
        }

        @Override
        public int hashCode() {
            return badDefaultPermission.hashCode();
        }

        @Override
        public String getActions() {
            return badDefaultPermission.getActions();
        }

    }

    // default policy file states:
    // "It is strongly recommended that you either remove this permission
    //  from this policy file or further restrict it to code sources
    //  that you specify, because Thread.stop() is potentially unsafe."
    // not even sure this method still works...
    private static final Permission BAD_DEFAULT_NUMBER_ONE =
            new BadDefaultPermission(new RuntimePermission("stopThread"), p -> true);

    // default policy file states:
    // "allows anyone to listen on dynamic ports"
    // specified exactly because that is what we want, and fastest since it won't imply any
    // expensive checks for the implicit "resolve"
    private static final Permission BAD_DEFAULT_NUMBER_TWO =
        new BadDefaultPermission(
            new SocketPermission("localhost:0", "listen"),
            // we apply this pre-implies test because some SocketPermission#implies calls do expensive reverse-DNS resolves
            p -> p instanceof SocketPermission && p.getActions().contains("listen"));

    /**
     * Wraps the Java system policy, filtering out bad default permissions that
     * are granted to all domains. Note, before java 8 these were even worse.
     */
    static class SystemPolicy extends Policy {
        final Policy delegate;

        SystemPolicy(Policy delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            if (BAD_DEFAULT_NUMBER_ONE.implies(permission) || BAD_DEFAULT_NUMBER_TWO.implies(permission)) {
                return false;
            }
            return delegate.implies(domain, permission);
        }
    }
}

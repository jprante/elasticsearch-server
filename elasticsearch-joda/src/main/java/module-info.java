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
module org.xbib.elasticsearch.joda {
    exports org.joda.time;
    exports org.joda.time.chrono;
    exports org.joda.time.field;
    exports org.joda.time.format;
    exports org.joda.time.tz;

    opens org.joda.time.tz.data;
    opens org.joda.time.tz.data.Africa;
    opens org.joda.time.tz.data.America;
    opens org.joda.time.tz.data.Antarctica;
    opens org.joda.time.tz.data.Arctic;
    opens org.joda.time.tz.data.Asia;
    opens org.joda.time.tz.data.Atlantic;
    opens org.joda.time.tz.data.Australia;
    opens org.joda.time.tz.data.Etc;
    opens org.joda.time.tz.data.Europe;
    opens org.joda.time.tz.data.Indian;
    opens org.joda.time.tz.data.Pacific;

}

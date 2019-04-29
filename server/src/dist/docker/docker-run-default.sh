#!/bin/sh

docker run --rm \
  --user elasticsearch \
  -p 9200:9200 -p 9300:9300 \
  --name elasticsearch \
  fl.hbz-nrw.de/jprante/elasticsearch-server:6.3.2.3 \
  java \
  -Dfile.encoding=UTF-8 \
  -Djava.awt.headless=true \
  -Dlog4j2.debug=false \
  -Dlog4j2.disable.jmx=true \
  -Dlog4j.shutdownHookEnabled=false \
  -Dio.netty.allocator.type=pooled \
  -Dio.netty.noUnsafe=true \
  -Dio.netty.recycler.maxCapacity=0 \
  -Dio.netty.noKeySetOptimization=true \
  -Djna.nosys=true \
  -Des.path.home="/elasticsearch" \
  -Des.path.conf="/elasticsearch/conf" \
  -Des.distribution.flavor="oss" \
  -Des.distribution.type="tar" \
  --patch-module java.base=/elasticsearch/lib/patch/java.beans \
  --add-exports java.base/java.beans=org.xbib.elasticsearch.log4j \
  --add-modules=jdk.unsupported \
  --add-exports=jdk.unsupported/sun.misc=org.xbib.elasticsearch.lucene \
  --add-exports=java.base/jdk.internal.ref=org.xbib.elasticsearch.lucene \
  --add-exports=java.base/jdk.internal.misc=org.xbib.elasticsearch.lucene \
  --add-exports=java.base/sun.nio.ch=org.xbib.elasticsearch.lucene \
  --module-path /elasticsearch/lib \
  --module org.xbib.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch \
  -Ebootstrap.memory_lock=false \
  -Enetwork.host="0.0.0.0"

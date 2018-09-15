#!/bin/sh

docker run --rm \
  --user elasticsearch \
  -p 9200:9200 -p 9300:9300 \
  --name elasticsearch \
  fl.hbz-nrw.de/jprante/elasticsearch-server-extended:6.3.2.0 \
  java \
  -XX:UseAVX=2 \
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
  --module-path /elasticsearch/lib \
  --module org.xbib.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch \
  -Ebootstrap.memory_lock=false \
  -Enetwork.host="0.0.0.0"

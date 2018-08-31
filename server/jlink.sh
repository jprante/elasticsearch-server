/Library/Java/JavaVirtualMachines/zulu-10.jdk/Contents/Home/bin/jlink \
      --module-path $JAVA_HOME/jmods:lib/ \
      --add-modules org.xbib.elasticsearch.server \
      --launcher run=org.xbib.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch \
      --compress 2 \
      --no-header-files \
      --no-man-pages \
      --verbose \
      --output tmp
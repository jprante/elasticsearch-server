FROM fl.hbz-nrw.de/jprante/alpine-glibc-openjdk10 AS builder

COPY elasticsearch-xbib*.tar.gz /

RUN tar -zxf /elasticsearch-xbib*.tar.gz && \
    jlink \
      --module-path $JAVA_HOME/jmods:/elasticsearch-6.3.2.0/lib \
      --add-modules org.xbib.elasticsearch.server \
      --launcher run=org.xbib.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch \
      --compress 2 \
      --no-header-files \
      --no-man-pages \
      --verbose \
      --output /elasticsearch-6.3.2.0 && \
    rm -f /elasticsearch-6.3.2.0/lib/elasticsearch*.jar && \
    rm -f /elasticsearch-xbib*.tar.gz

FROM fl.hbz-nrw.de/jprante/alpine-glibc

COPY --from=builder /elasticsearch-6.3.2.0 /elasticsearch

ENV JAVA_HOME=/elasticsearch \
    PATH=$PATH:/elasticsearch/bin

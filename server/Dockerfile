FROM fl.hbz-nrw.de/jprante/alpine-glibc-openjdk10 AS builder

COPY build/distributions/elasticsearch-server-default.java-1.10-6.3.2.0.tar.gz /

RUN tar -zxf /elasticsearch*.tar.gz && \
    jlink \
      --module-path $JAVA_HOME/jmods:/elasticsearch-6.3.2.0/lib \
      --add-modules org.xbib.elasticsearch.server \
      --launcher run=org.xbib.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch \
      --compress 2 \
      --no-header-files \
      --no-man-pages \
      --verbose \
      --output /elasticsearch && \
    rm -rf /elasticsearch-6.3.2.0 /elasticsearch*.tar.gz

FROM fl.hbz-nrw.de/jprante/alpine-glibc

COPY --from=builder /elasticsearch /elasticsearch

ENV JAVA_HOME=/elasticsearch \
    PATH=$PATH:/elasticsearch/bin

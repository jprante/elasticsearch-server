module org.xbib.elasticsearch.transport.nettyfour {
    exports org.elasticsearch.transport.netty4;
    exports org.elasticsearch.http.netty4;
    exports org.elasticsearch.http.netty4.cors;
    exports org.elasticsearch.http.netty4.pipelining;

    requires org.xbib.elasticsearch.netty;

    requires static org.xbib.elasticsearch.lucene;
    requires static org.xbib.elasticsearch.hppc;
    requires static org.xbib.elasticsearch.log4j;
    requires static org.xbib.elasticsearch.server;
}

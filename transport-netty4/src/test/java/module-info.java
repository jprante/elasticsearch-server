module org.xbib.elasticsearch.transport.nettyfour.test {

    exports org.elasticsearch.test.http.netty4;
    exports org.elasticsearch.test.http.netty4.pipelining;
    exports org.elasticsearch.test.transport.netty4;
    exports org.elasticsearch.test.rest.netty4;
    exports org.elasticsearch.testframework.netty4;

    requires junit;
    requires hamcrest.all;
    requires httpcore;
    requires org.xbib.elasticsearch.testframework;
    requires org.xbib.elasticsearch.lucene;
    requires org.xbib.elasticsearch.lucene.testframework;
    requires org.xbib.elasticsearch.transport.nettyfour;
    requires org.xbib.elasticsearch.netty;
    requires org.xbib.elasticsearch.client.rest;
    requires org.xbib.elasticsearch.server;
    requires org.xbib.elasticsearch.randomizedtesting;
    requires org.xbib.elasticsearch.mocksocket;
    requires org.xbib.elasticsearch.log4j;
}

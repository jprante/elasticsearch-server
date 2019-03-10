package org.elasticsearch.analysis.common;

import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.miscellaneous.TruncateTokenFilter;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.analysis.AbstractTokenFilterFactory;

public class TruncateTokenFilterFactory extends AbstractTokenFilterFactory {

    private final int length;

    TruncateTokenFilterFactory(IndexSettings indexSettings, Environment environment, String name, Settings settings) {
        super(indexSettings, name, settings);
        this.length = settings.getAsInt("length", -1);
        if (length <= 0) {
            throw new IllegalArgumentException("length parameter must be provided");
        }
    }

    @Override
    public TokenStream create(TokenStream tokenStream) {
        return new TruncateTokenFilter(tokenStream, length);
    }
}

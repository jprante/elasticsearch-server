package org.elasticsearch.analysis.common;

import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.miscellaneous.ASCIIFoldingFilter;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.analysis.AbstractTokenFilterFactory;
import org.elasticsearch.index.analysis.MultiTermAwareComponent;
import org.elasticsearch.index.analysis.TokenFilterFactory;

/**
 * Factory for ASCIIFoldingFilter.
 */
public class ASCIIFoldingTokenFilterFactory extends AbstractTokenFilterFactory
        implements MultiTermAwareComponent {
    public static final ParseField PRESERVE_ORIGINAL = new ParseField("preserve_original");
    public static final boolean DEFAULT_PRESERVE_ORIGINAL = false;

    private final boolean preserveOriginal;

    public ASCIIFoldingTokenFilterFactory(IndexSettings indexSettings, Environment environment,
            String name, Settings settings) {
        super(indexSettings, name, settings);
        preserveOriginal = settings.getAsBooleanLenientForPreEs6Indices(
                indexSettings.getIndexVersionCreated(), PRESERVE_ORIGINAL.getPreferredName(),
                DEFAULT_PRESERVE_ORIGINAL, deprecationLogger);
    }

    @Override
    public TokenStream create(TokenStream tokenStream) {
        return new ASCIIFoldingFilter(tokenStream, preserveOriginal);
    }

    @Override
    public Object getMultiTermComponent() {
        if (preserveOriginal == false) {
            return this;
        } else {
            // See https://issues.apache.org/jira/browse/LUCENE-7536 for the reasoning
            return new TokenFilterFactory() {
                @Override
                public String name() {
                    return ASCIIFoldingTokenFilterFactory.this.name();
                }
                @Override
                public TokenStream create(TokenStream tokenStream) {
                    return new ASCIIFoldingFilter(tokenStream, false);
                }
            };
        }
    }
}

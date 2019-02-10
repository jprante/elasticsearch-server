package org.elasticsearch.test.plugins.spi;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.plugins.spi.NamedXContentProvider;
import org.elasticsearch.search.aggregations.Aggregation;
import org.elasticsearch.search.aggregations.pipeline.ParsedSimpleValue;
import org.elasticsearch.search.suggest.Suggest;
import org.elasticsearch.search.suggest.term.TermSuggestion;

import java.util.Arrays;
import java.util.List;

public class DummyNamedXContentProvider implements NamedXContentProvider {

        public DummyNamedXContentProvider() {
        }

        @Override
        public List<NamedXContentRegistry.Entry> getNamedXContentParsers() {
            return Arrays.asList(
                    new NamedXContentRegistry.Entry(Aggregation.class, new ParseField("test_aggregation"),
                            (parser, context) -> ParsedSimpleValue.fromXContent(parser, (String) context)),
                    new NamedXContentRegistry.Entry(Suggest.Suggestion.class, new ParseField("test_suggestion"),
                            (parser, context) -> TermSuggestion.fromXContent(parser, (String) context))
            );
        }
    }
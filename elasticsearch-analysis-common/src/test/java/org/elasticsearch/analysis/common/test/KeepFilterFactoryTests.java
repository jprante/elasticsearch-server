package org.elasticsearch.analysis.common.test;

import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.elasticsearch.analysis.common.CommonAnalysisPlugin;
import org.elasticsearch.analysis.common.KeepWordFilterFactory;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.testframework.index.analysis.AnalysisTestsHelper;
import org.elasticsearch.index.analysis.TokenFilterFactory;
import org.elasticsearch.testframework.ESTestCase;
import org.elasticsearch.testframework.ESTokenStreamTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.io.StringReader;

import static org.hamcrest.Matchers.instanceOf;

public class KeepFilterFactoryTests extends ESTokenStreamTestCase {
    private static final String RESOURCE = "/org/elasticsearch/analysis/common/test/keep_analysis.json";

    public void testLoadWithoutSettings() throws IOException {
        ESTestCase.TestAnalysis analysis = AnalysisTestsHelper.createTestAnalysisFromClassPath(getClass(),
                createTempDir(), RESOURCE, new CommonAnalysisPlugin());
        TokenFilterFactory tokenFilter = analysis.tokenFilter.get("keep");
        Assert.assertNull(tokenFilter);
    }

    public void testLoadOverConfiguredSettings() {
        Settings settings = Settings.builder()
                .put(Environment.PATH_HOME_SETTING.getKey(), createTempDir().toString())
                .put("index.analysis.filter.broken_keep_filter.type", "keep")
                .put("index.analysis.filter.broken_keep_filter.keep_words_path", "does/not/exists.txt")
                .put("index.analysis.filter.broken_keep_filter.keep_words", "[\"Hello\", \"worlD\"]")
                .build();
        try {
            AnalysisTestsHelper.createTestAnalysisFromSettings(settings, new CommonAnalysisPlugin());
            Assert.fail("path and array are configured");
        } catch (IllegalArgumentException e) {
        } catch (IOException e) {
            fail("expected IAE");
        }
    }

    public void testKeepWordsPathSettings() {
        Settings settings = Settings.builder()
                .put(Environment.PATH_HOME_SETTING.getKey(), createTempDir().toString())
                .put("index.analysis.filter.non_broken_keep_filter.type", "keep")
                .put("index.analysis.filter.non_broken_keep_filter.keep_words_path", "does/not/exists.txt")
                .build();
        try {
            // test our none existing setup is picked up
            AnalysisTestsHelper.createTestAnalysisFromSettings(settings, new CommonAnalysisPlugin());
            fail("expected an exception due to non existent keep_words_path");
        } catch (IllegalArgumentException e) {
        } catch (IOException e) {
            fail("expected IAE");
        }

        settings = Settings.builder().put(settings)
                .putList("index.analysis.filter.non_broken_keep_filter.keep_words", "test")
                .build();
        try {
            // test our none existing setup is picked up
            AnalysisTestsHelper.createTestAnalysisFromSettings(settings, new CommonAnalysisPlugin());
            fail("expected an exception indicating that you can't use [keep_words_path] with [keep_words] ");
        } catch (IllegalArgumentException e) {
        } catch (IOException e) {
            fail("expected IAE");
        }
    }

    public void testCaseInsensitiveMapping() throws IOException {
        ESTestCase.TestAnalysis analysis = AnalysisTestsHelper.createTestAnalysisFromClassPath(getClass(),
                createTempDir(), RESOURCE, new CommonAnalysisPlugin());
        TokenFilterFactory tokenFilter = analysis.tokenFilter.get("my_keep_filter");
        assertThat(tokenFilter, instanceOf(KeepWordFilterFactory.class));
        String source = "hello small world";
        String[] expected = new String[]{"hello", "world"};
        Tokenizer tokenizer = new WhitespaceTokenizer();
        tokenizer.setReader(new StringReader(source));
        assertTokenStreamContents(tokenFilter.create(tokenizer), expected, new int[]{1, 2});
    }

    public void testCaseSensitiveMapping() throws IOException {
        ESTestCase.TestAnalysis analysis = AnalysisTestsHelper.createTestAnalysisFromClassPath(getClass(),
                createTempDir(), RESOURCE, new CommonAnalysisPlugin());
        TokenFilterFactory tokenFilter = analysis.tokenFilter.get("my_case_sensitive_keep_filter");
        assertThat(tokenFilter, instanceOf(KeepWordFilterFactory.class));
        String source = "Hello small world";
        String[] expected = new String[]{"Hello"};
        Tokenizer tokenizer = new WhitespaceTokenizer();
        tokenizer.setReader(new StringReader(source));
        assertTokenStreamContents(tokenFilter.create(tokenizer), expected, new int[]{1});
    }
}

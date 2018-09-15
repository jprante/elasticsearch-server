package com.fasterxml.jackson.databind.ext;

import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.AnnotatedParameter;
import com.fasterxml.jackson.databind.introspect.AnnotatedWithParams;

import java.nio.file.Path;

/**
 * @since 2.8
 */
public class Java7SupportImpl extends Java7Support
{

    public Java7SupportImpl() {
    }

    @Override
    public Class<?> getClassJavaNioFilePath() {
        return Path.class;
    }

    @Override
    public JsonDeserializer<?> getDeserializerForJavaNioFilePath(Class<?> rawType) {
        if (rawType == Path.class) {
            return new NioPathDeserializer();
        }
        return null;
    }

    @Override
    public JsonSerializer<?> getSerializerForJavaNioFilePath(Class<?> rawType) {
        if (Path.class.isAssignableFrom(rawType)) {
            return new NioPathSerializer();
        }
        return null;
    }

    @Override
    public Boolean findTransient(Annotated a) {
        return null;
    }

    @Override
    public Boolean hasCreatorAnnotation(Annotated a) {
        return null;
    }

    @Override
    public PropertyName findConstructorName(AnnotatedParameter p)
    {
        return null;
    }
}

package lite.beans;

import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Documented
@Target(CONSTRUCTOR)
@Retention(RUNTIME)
public @interface ConstructorProperties {

    /**
     * <p>The getter names.</p>
     *
     * @return the getter names corresponding to the parameters in the annotated constructor.
     */
    String[] value();
}

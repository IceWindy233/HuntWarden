package io.huntwarden.probe;

import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SpringMvcInspectorTest {
    public static final class Controller { public void health() {} }
    public static final class Interceptor {}
    public static final class Handler {
        public Class<?> getBeanType() { return Controller.class; }
        public Method getMethod() throws NoSuchMethodException { return Controller.class.getMethod("health"); }
    }
    public static final class Context {
        private final RequestMappingHandlerMapping mapping = new RequestMappingHandlerMapping(
                Map.of("{GET [/health]}", new Handler()), List.of(new Interceptor()));
        public Map<String, Object> getBeansOfType(Class<?> type) { return Map.of("requestMappingHandlerMapping", mapping); }
    }
    public static final class DispatcherServlet {
        public Context getWebApplicationContext() { return new Context(); }
    }

    @Test
    void enumeratesControllersAndInterceptorsWithoutMutatingContext() {
        SpringMvcInspector.ScanResult result = SpringMvcInspector.inspect(new DispatcherServlet());
        assertTrue(result.applicable());
        assertFalse(result.truncated());
        assertTrue(result.components().stream().anyMatch(value -> value.type().equals("spring_controller")
                && value.componentClass().equals(Controller.class) && value.mapping().contains("/health")));
        assertTrue(result.components().stream().anyMatch(value -> value.type().equals("spring_interceptor")
                && value.componentClass().equals(Interceptor.class)));
    }

    @Test
    void ignoresNonSpringServlets() {
        SpringMvcInspector.ScanResult result = SpringMvcInspector.inspect(new Object());
        assertFalse(result.applicable());
        assertTrue(result.components().isEmpty());
    }
}

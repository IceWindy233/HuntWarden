package org.springframework.web.servlet.mvc.method.annotation;

import java.util.List;
import java.util.Map;

/** Test-only shape used to validate bounded reflection without a Spring runtime dependency. */
public final class RequestMappingHandlerMapping {
    private final Map<Object, Object> handlerMethods;
    private final List<Object> adaptedInterceptors;

    public RequestMappingHandlerMapping(Map<Object, Object> handlerMethods, List<Object> interceptors) {
        this.handlerMethods = handlerMethods;
        this.adaptedInterceptors = interceptors;
    }

    public Map<Object, Object> getHandlerMethods() { return handlerMethods; }
    public List<Object> getMappedInterceptors() { return List.of(); }
}

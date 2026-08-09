package io.huntwarden.probe;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded, getter-only inspection of an already initialized Spring DispatcherServlet. */
final class SpringMvcInspector {
    private static final int MAX_HANDLER_MAPPINGS = 32;
    private static final int MAX_CONTROLLERS = 512;
    private static final int MAX_INTERCEPTORS = 256;

    record Component(String type, String name, Class<?> componentClass, String mapping, String source) {}
    record ScanResult(boolean applicable, List<Component> components, List<String> warnings, boolean truncated) {}

    private SpringMvcInspector() {}

    static ScanResult inspect(Object servlet) {
        Method contextMethod = publicMethod(servlet.getClass(), "getWebApplicationContext");
        if (contextMethod == null) return new ScanResult(false, List.of(), List.of(), false);
        List<Component> components = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        boolean truncated = false;
        try {
            Object context = contextMethod.invoke(servlet);
            if (context == null) return new ScanResult(true, List.of(), List.of("Spring WebApplicationContext 尚未初始化"), false);
            ClassLoader loader = servlet.getClass().getClassLoader();
            Class<?> mappingClass = Class.forName(
                    "org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping", false, loader);
            Method beansMethod = publicMethod(context.getClass(), "getBeansOfType", Class.class);
            if (beansMethod == null) return new ScanResult(true, List.of(), List.of("WebApplicationContext 不提供 getBeansOfType"), false);
            Object beansValue = beansMethod.invoke(context, mappingClass);
            if (!(beansValue instanceof Map<?, ?> beans)) {
                return new ScanResult(true, List.of(), List.of("RequestMappingHandlerMapping Bean 结果不是 Map"), false);
            }
            int mappingBeans = 0;
            Set<Object> interceptors = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
            for (Map.Entry<?, ?> beanEntry : beans.entrySet()) {
                if (mappingBeans++ >= MAX_HANDLER_MAPPINGS) { truncated = true; break; }
                Object mappingBean = beanEntry.getValue();
                if (mappingBean == null) continue;
                Method handlersMethod = publicMethod(mappingBean.getClass(), "getHandlerMethods");
                Object handlerValue = handlersMethod == null ? null : handlersMethod.invoke(mappingBean);
                if (handlerValue instanceof Map<?, ?> handlers) {
                    for (Map.Entry<?, ?> handlerEntry : handlers.entrySet()) {
                        if (components.stream().filter(value -> value.type().equals("spring_controller")).count() >= MAX_CONTROLLERS) {
                            truncated = true;
                            break;
                        }
                        Object handler = handlerEntry.getValue();
                        Class<?> beanType = classValue(invokeOptional(handler, "getBeanType"));
                        Object method = invokeOptional(handler, "getMethod");
                        if (beanType == null) continue;
                        String methodName = method instanceof Method value ? value.toGenericString() : String.valueOf(method);
                        components.add(new Component("spring_controller", bounded(methodName, 2048), beanType,
                                bounded(String.valueOf(handlerEntry.getKey()), 2048), "request_mapping_handler"));
                    }
                } else {
                    warnings.add("RequestMappingHandlerMapping 未返回 handlerMethods Map");
                }
                collectValues(readField(mappingBean, "adaptedInterceptors"), interceptors);
                collectValues(invokeOptional(mappingBean, "getMappedInterceptors"), interceptors);
            }
            int count = 0;
            for (Object interceptor : interceptors) {
                if (interceptor == null) continue;
                if (count++ >= MAX_INTERCEPTORS) { truncated = true; break; }
                components.add(new Component("spring_interceptor", interceptor.getClass().getName(),
                        interceptor.getClass(), null, "handler_mapping"));
            }
        } catch (ClassNotFoundException ignored) {
            return new ScanResult(false, List.of(), List.of(), false);
        } catch (Throwable error) {
            warnings.add(error.getClass().getName() + ": " + bounded(String.valueOf(error.getMessage()), 1024));
        }
        return new ScanResult(true, List.copyOf(components), deduplicate(warnings), truncated);
    }

    private static Method publicMethod(Class<?> type, String name, Class<?>... parameters) {
        try { return type.getMethod(name, parameters); }
        catch (ReflectiveOperationException ignored) { return null; }
    }

    private static Object invokeOptional(Object target, String name) {
        if (target == null) return null;
        Method method = publicMethod(target.getClass(), name);
        try { return method == null ? null : method.invoke(target); }
        catch (ReflectiveOperationException ignored) { return null; }
    }

    private static Object readField(Object target, String name) {
        if (target == null) return null;
        for (Class<?> type = target.getClass(); type != null && type != Object.class; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                if (!field.trySetAccessible()) return null;
                return field.get(target);
            } catch (ReflectiveOperationException | RuntimeException ignored) {
                // Spring versions place the field in different superclasses.
            }
        }
        return null;
    }

    private static void collectValues(Object value, Set<Object> destination) {
        if (value == null) return;
        if (value instanceof Collection<?> collection) { destination.addAll(collection); return; }
        if (value.getClass().isArray()) {
            for (int index = 0; index < Array.getLength(value); index++) destination.add(Array.get(value, index));
        }
    }

    private static Class<?> classValue(Object value) { return value instanceof Class<?> type ? type : null; }
    private static String bounded(String value, int maximum) { return value.length() <= maximum ? value : value.substring(0, maximum); }
    private static List<String> deduplicate(List<String> values) { return List.copyOf(new LinkedHashSet<>(values)); }
}

package io.huntwarden.probe;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Bounded, read-only inspection of Tomcat's WebSocket server container.
 *
 * <p>The WebSocket API intentionally has no endpoint enumeration method. Tomcat 8.5, 9 and 10
 * keep the registered mappings in implementation-private maps, whose concrete wrapper classes
 * vary between releases. This inspector therefore walks only map/collection/array values and
 * Tomcat WebSocket implementation objects, stops at a small fixed depth and never invokes a
 * mutating method.</p>
 */
final class WebSocketInspector {
    static final int MAX_NODES = 2_048;
    static final int MAX_DEPTH = 6;
    static final int MAX_REFLECTION_ERRORS = 64;

    private WebSocketInspector() {}

    record Endpoint(String path, Class<?> endpointClass) {}

    record ScanResult(List<Endpoint> endpoints, List<String> reflectionErrors, boolean truncated) {}

    static ScanResult inspect(Object serverContainer) {
        if (serverContainer == null) return new ScanResult(List.of(), List.of(), false);

        Deque<Node> queue = new ArrayDeque<>();
        Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Map<String, Endpoint> endpoints = new LinkedHashMap<>();
        Set<String> errors = new LinkedHashSet<>();
        queue.add(new Node(serverContainer, 0));
        int visitedNodes = 0;
        boolean truncated = false;

        while (!queue.isEmpty()) {
            Node node = queue.removeFirst();
            Object value = node.value();
            if (value == null || isScalar(value) || !visited.add(value)) continue;
            if (++visitedNodes > MAX_NODES) {
                truncated = true;
                break;
            }

            extractEndpoint(value, endpoints, errors);
            if (node.depth() >= MAX_DEPTH) {
                if (isTraversable(value)) truncated = true;
                continue;
            }

            try {
                if (value instanceof Map<?, ?> map) {
                    for (Map.Entry<?, ?> entry : map.entrySet()) {
                        enqueue(queue, entry.getKey(), node.depth() + 1);
                        enqueue(queue, entry.getValue(), node.depth() + 1);
                    }
                } else if (value instanceof Collection<?> collection) {
                    for (Object item : collection) enqueue(queue, item, node.depth() + 1);
                } else if (value instanceof Iterable<?> iterable) {
                    for (Object item : iterable) enqueue(queue, item, node.depth() + 1);
                } else if (value instanceof Optional<?> optional) {
                    optional.ifPresent(item -> enqueue(queue, item, node.depth() + 1));
                } else if (value.getClass().isArray()) {
                    int length = Array.getLength(value);
                    for (int index = 0; index < length; index++) {
                        enqueue(queue, Array.get(value, index), node.depth() + 1);
                    }
                } else if (shouldInspectFields(value.getClass(), value == serverContainer)) {
                    inspectFields(value, node.depth(), queue, errors);
                }
            } catch (Throwable error) {
                addError(errors, describe(value.getClass()) + " traversal: " + describe(error));
            }
        }

        return new ScanResult(List.copyOf(endpoints.values()), List.copyOf(errors), truncated);
    }

    private static void extractEndpoint(Object value, Map<String, Endpoint> endpoints, Set<String> errors) {
        Method getPath = publicNoArg(value.getClass(), "getPath");
        Method getEndpointClass = publicNoArg(value.getClass(), "getEndpointClass");
        if (getPath == null || getEndpointClass == null) return;
        try {
            Object rawPath = getPath.invoke(value);
            Object rawClass = getEndpointClass.invoke(value);
            if (!(rawPath instanceof String path) || path.isBlank() || !(rawClass instanceof Class<?> endpointClass)) return;
            String loader = endpointClass.getClassLoader() == null
                    ? "bootstrap"
                    : endpointClass.getClassLoader().getClass().getName() + "@"
                    + Integer.toHexString(System.identityHashCode(endpointClass.getClassLoader()));
            endpoints.putIfAbsent(path + "\n" + endpointClass.getName() + "\n" + loader,
                    new Endpoint(path, endpointClass));
        } catch (Throwable error) {
            addError(errors, describe(value.getClass()) + " endpoint getters: " + describe(error));
        }
    }

    private static void inspectFields(Object owner, int depth, Deque<Node> queue, Set<String> errors) {
        Class<?> current = owner.getClass();
        int inspectedFields = 0;
        while (current != null && current != Object.class && inspectedFields < 128) {
            for (Field field : current.getDeclaredFields()) {
                if (++inspectedFields > 128) return;
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) continue;
                String fieldName = field.getName().toLowerCase(Locale.ROOT);
                if (!isMappingField(fieldName, field.getType())) continue;
                try {
                    if (!field.canAccess(owner) && !field.trySetAccessible()) {
                        addError(errors, describe(current) + "#" + field.getName() + ": inaccessible");
                        continue;
                    }
                    Object child = field.get(owner);
                    if (child == null || isAllowedChild(child)) enqueue(queue, child, depth + 1);
                } catch (Throwable error) {
                    addError(errors, describe(current) + "#" + field.getName() + ": " + describe(error));
                }
            }
            current = current.getSuperclass();
        }
    }

    private static boolean isMappingField(String name, Class<?> type) {
        return name.contains("config") || name.contains("endpoint") || name.contains("mapping")
                || name.contains("match") || name.contains("path") || Map.class.isAssignableFrom(type)
                || Collection.class.isAssignableFrom(type) || Iterable.class.isAssignableFrom(type)
                || Optional.class.isAssignableFrom(type) || type.isArray();
    }

    private static boolean isAllowedChild(Object value) {
        return isTraversable(value) || shouldInspectFields(value.getClass(), false)
                || (publicNoArg(value.getClass(), "getPath") != null
                && publicNoArg(value.getClass(), "getEndpointClass") != null);
    }

    private static boolean shouldInspectFields(Class<?> type, boolean root) {
        if (root) return true;
        String name = type.getName().toLowerCase(Locale.ROOT);
        return name.startsWith("org.apache.tomcat.websocket.") || name.contains("websocket")
                || name.contains("wsservercontainer") || name.contains("serverendpoint")
                || name.contains("endpointconfig") || name.contains("pathmatch");
    }

    private static boolean isTraversable(Object value) {
        return value instanceof Map<?, ?> || value instanceof Collection<?> || value instanceof Iterable<?>
                || value instanceof Optional<?> || value.getClass().isArray();
    }

    private static void enqueue(Deque<Node> queue, Object value, int depth) {
        if (value != null && !isScalar(value)) queue.addLast(new Node(value, depth));
    }

    private static Method publicNoArg(Class<?> type, String name) {
        try {
            Method method = type.getMethod(name);
            return method.getParameterCount() == 0 ? method : null;
        } catch (NoSuchMethodException ignored) {
            return null;
        }
    }

    private static boolean isScalar(Object value) {
        return value instanceof String || value instanceof Number || value instanceof Boolean
                || value instanceof Character || value instanceof Enum<?> || value instanceof Class<?>;
    }

    private static void addError(Set<String> errors, String value) {
        if (errors.size() < MAX_REFLECTION_ERRORS) errors.add(value);
    }

    private static String describe(Class<?> type) {
        return type == null ? "unknown" : type.getName();
    }

    private static String describe(Throwable error) {
        Throwable cause = error.getCause() == null ? error : error.getCause();
        String message = cause.getMessage();
        return cause.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : ": " + message);
    }

    private record Node(Object value, int depth) {}
}

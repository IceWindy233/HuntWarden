package io.huntwarden.probe;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.module.ModuleDescriptor;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static java.lang.management.ManagementFactory.getPlatformMBeanServer;

public final class ProbeAgent {
    private ProbeAgent() {}

    public static void agentmain(String encodedRequest, Instrumentation instrumentation) {
        Path output = null;
        Map<String, Object> response;
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(encodedRequest), StandardCharsets.UTF_8);
            String[] parts = decoded.split("\\n", -1);
            if (parts.length != 3 && parts.length != 4) throw new IllegalArgumentException("invalid request");
            String command = parts[0];
            String className = parts[1];
            String classLoaderId = parts.length == 4 && !parts[2].isBlank() ? parts[2] : null;
            output = Path.of(parts[parts.length - 1]);
            response = switch (command) {
                case "list_components" -> listComponents(instrumentation);
                case "inspect_class" -> inspectClass(instrumentation, className, classLoaderId);
                case "dump_class" -> dumpClass(instrumentation, className, classLoaderId);
                default -> throw new IllegalArgumentException("unsupported command");
            };
        } catch (Throwable error) {
            response = new LinkedHashMap<>();
            response.put("partial", true);
            response.put("error", error.getClass().getSimpleName() + ": " + error.getMessage());
        }
        if (output != null) {
            try {
                Files.writeString(output, Json.stringify(response), StandardCharsets.UTF_8);
            } catch (IOException ignored) {
                // The attach launcher will time out and report a collection error.
            }
        }
    }

    private static Map<String, Object> listComponents(Instrumentation instrumentation) throws Exception {
        MBeanServer server = getPlatformMBeanServer();
        Set<ObjectName> names = server.queryNames(null, null);
        DiagnosticLog diagnosticLog = new DiagnosticLog();
        List<Map<String, Object>> discovered = new ArrayList<>();
        discovered.addAll(listContextComponents(instrumentation, diagnosticLog));
        discovered.addAll(listJmxComponents(instrumentation, server, names));

        Map<String, Map<String, Object>> unique = new LinkedHashMap<>();
        for (Map<String, Object> component : discovered) unique.putIfAbsent(componentKey(component), component);
        List<Map<String, Object>> components = new ArrayList<>(unique.values());
        components.sort(Comparator.comparing(value -> String.valueOf(value.get("type")) + "\n"
                + String.valueOf(value.get("context")) + "\n" + String.valueOf(value.get("name"))));

        RuntimeDiagnostics.Section jvm = RuntimeDiagnostics.collectJvm();
        RuntimeDiagnostics.Section threads = RuntimeDiagnostics.collectThreads();
        RuntimeDiagnostics.Section network = RuntimeDiagnostics.collectNetwork(server, names);
        diagnosticLog.add(jvm.collectorStatus());
        diagnosticLog.add(threads.collectorStatus());
        diagnosticLog.add(network.collectorStatus());

        List<String> warnings = new ArrayList<>(diagnosticLog.warnings());
        warnings.addAll(jvm.warnings());
        warnings.addAll(threads.warnings());
        warnings.addAll(network.warnings());
        if (components.isEmpty()) warnings.add("Tomcat 中未发现 Filter/Servlet/Listener/Valve/WebSocket Endpoint；容器可能尚未部署应用或版本不兼容");

        Map<String, Object> diagnostics = new LinkedHashMap<>();
        diagnostics.put("collectors", diagnosticLog.entries());
        diagnostics.put("jvm", jvm.data());
        diagnostics.put("threads", threads.data());
        diagnostics.put("network", network.data());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("components", components);
        result.put("diagnostics", diagnostics);
        result.put("warnings", warnings.stream().distinct().toList());
        result.put("partial", components.isEmpty() || diagnosticLog.partial() || jvm.partial() || threads.partial() || network.partial());
        return result;
    }

    private static List<Map<String, Object>> listContextComponents(Instrumentation instrumentation, DiagnosticLog diagnostics) {
        List<Map<String, Object>> components = new ArrayList<>();
        Set<ClassLoader> loaders = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            ClassLoader loader = loaded.getClassLoader();
            if (loader != null && loader.getClass().getName().toLowerCase(Locale.ROOT).contains("webappclassloader")) loaders.add(loader);
        }
        if (loaders.isEmpty()) {
            diagnostics.notPresent("tomcat_context_discovery", null, "未发现 Tomcat WebappClassLoader");
            return components;
        }
        diagnostics.ok("tomcat_context_discovery", null, loaders.size());

        Set<Object> visitedContexts = Collections.newSetFromMap(new IdentityHashMap<>());
        for (ClassLoader loader : loaders) {
            Object context;
            try {
                Object resources = invoke(loader, "getResources");
                context = invoke(resources, "getContext");
            } catch (Throwable error) {
                diagnostics.partial("tomcat_context_reflection", loaderId(loader), List.of(describe(error)));
                continue;
            }
            if (context == null || !visitedContexts.add(context)) continue;
            String contextName;
            try {
                contextName = String.valueOf(invoke(context, "getName"));
            } catch (Throwable error) {
                contextName = context.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(context));
                diagnostics.partial("tomcat_context_identity", contextName, List.of(describe(error)));
            }
            final String resolvedContextName = contextName;

            collectContextPart("tomcat_filters", resolvedContextName, diagnostics,
                    () -> collectFilters(instrumentation, components, context, resolvedContextName, loader));
            collectContextPart("tomcat_servlets", resolvedContextName, diagnostics,
                    () -> collectServlets(instrumentation, components, context, resolvedContextName, loader));
            collectContextPart("tomcat_listeners", resolvedContextName, diagnostics,
                    () -> collectListeners(instrumentation, components, context, resolvedContextName, loader));
            collectContextPart("tomcat_valves", resolvedContextName, diagnostics,
                    () -> collectValves(instrumentation, components, context, resolvedContextName));
            collectWebSockets(instrumentation, components, context, resolvedContextName, diagnostics);
        }
        return components;
    }

    private static int collectFilters(Instrumentation instrumentation, List<Map<String, Object>> components,
                                      Object context, String contextName, ClassLoader loader) throws Exception {
        int count = 0;
        for (Object filter : array(invoke(context, "findFilterDefs"))) {
            String name = String.valueOf(invoke(filter, "getFilterName"));
            String className = stringValue(invoke(filter, "getFilterClass"));
            Object instance = optionalInvoke(filter, "getFilter");
            if ((className == null || className.isBlank()) && instance != null) className = instance.getClass().getName();
            components.add(component(instrumentation, "filter", name, className, contextName,
                    instance == null ? "descriptor" : "runtime-instance", loader));
            count++;
        }
        return count;
    }

    private static int collectServlets(Instrumentation instrumentation, List<Map<String, Object>> components,
                                       Object context, String contextName, ClassLoader loader) throws Exception {
        int count = 0;
        for (Object wrapper : array(invoke(context, "findChildren"))) {
            String name = String.valueOf(invoke(wrapper, "getName"));
            String className = stringValue(optionalInvoke(wrapper, "getServletClass"));
            if (className != null && !className.isBlank()) {
                components.add(component(instrumentation, "servlet", name, className, contextName, "context-child", loader));
                count++;
            }
        }
        return count;
    }

    private static int collectListeners(Instrumentation instrumentation, List<Map<String, Object>> components,
                                        Object context, String contextName, ClassLoader loader) throws Exception {
        Set<String> listenerClasses = new LinkedHashSet<>();
        for (Object name : array(invoke(context, "findApplicationListeners"))) listenerClasses.add(String.valueOf(name));
        for (Object listener : array(optionalInvoke(context, "getApplicationEventListeners"))) {
            if (listener != null) listenerClasses.add(listener.getClass().getName());
        }
        for (String className : listenerClasses) {
            components.add(component(instrumentation, "listener", className, className, contextName, "runtime-context", loader));
        }
        return listenerClasses.size();
    }

    private static int collectValves(Instrumentation instrumentation, List<Map<String, Object>> components,
                                     Object context, String contextName) throws Exception {
        Set<Object> containers = Collections.newSetFromMap(new IdentityHashMap<>());
        Object container = context;
        int count = 0;
        int depth = 0;
        while (container != null && depth++ < 4 && containers.add(container)) {
            String containerName = String.valueOf(optionalInvoke(container, "getName"));
            Object pipeline = invoke(container, "getPipeline");
            for (Object valve : array(invoke(pipeline, "getValves"))) {
                if (valve == null) continue;
                String name = stringValue(optionalInvoke(valve, "getName"));
                if (name == null || name.isBlank() || "null".equals(name)) name = valve.getClass().getSimpleName();
                Map<String, Object> item = instanceComponent(instrumentation, "valve", name, valve, contextName, "runtime-pipeline");
                item.put("container", containerName);
                item.put("containerClass", container.getClass().getName());
                Object enabled = optionalInvoke(valve, "isEnabled");
                if (enabled instanceof Boolean) item.put("enabled", enabled);
                Object asyncSupported = optionalInvoke(valve, "isAsyncSupported");
                if (asyncSupported instanceof Boolean) item.put("asyncSupported", asyncSupported);
                components.add(item);
                count++;
            }
            container = optionalInvoke(container, "getParent");
        }
        return count;
    }

    private static void collectWebSockets(Instrumentation instrumentation, List<Map<String, Object>> components,
                                          Object context, String contextName, DiagnosticLog diagnostics) {
        Object servletContext;
        try {
            servletContext = invoke(context, "getServletContext");
        } catch (Throwable error) {
            diagnostics.partial("tomcat_websocket_endpoints", contextName, List.of(describe(error)));
            return;
        }
        Object serverContainer = null;
        List<String> lookupErrors = new ArrayList<>();
        for (String attribute : List.of("jakarta.websocket.server.ServerContainer", "javax.websocket.server.ServerContainer")) {
            try {
                Object value = invoke(servletContext, "getAttribute", new Class<?>[]{String.class}, attribute);
                if (value != null) {
                    serverContainer = value;
                    break;
                }
            } catch (Throwable error) {
                lookupErrors.add(attribute + ": " + describe(error));
            }
        }
        if (serverContainer == null) {
            if (lookupErrors.isEmpty()) diagnostics.notPresent("tomcat_websocket_endpoints", contextName, "未注册 WebSocket ServerContainer");
            else diagnostics.partial("tomcat_websocket_endpoints", contextName, lookupErrors);
            return;
        }

        WebSocketInspector.ScanResult scan = WebSocketInspector.inspect(serverContainer);
        for (WebSocketInspector.Endpoint endpoint : scan.endpoints()) {
            Map<String, Object> item = classComponent(instrumentation, "websocket_endpoint", endpoint.path(),
                    endpoint.endpointClass(), contextName, "runtime-websocket-container");
            item.put("endpointPath", endpoint.path());
            components.add(item);
        }
        List<String> errors = new ArrayList<>(lookupErrors);
        errors.addAll(scan.reflectionErrors());
        if (scan.truncated()) errors.add("WebSocket 映射对象图达到安全采集上限");
        if (errors.isEmpty()) diagnostics.ok("tomcat_websocket_endpoints", contextName, scan.endpoints().size());
        else diagnostics.partial("tomcat_websocket_endpoints", contextName, errors);
    }

    private static List<Map<String, Object>> listJmxComponents(Instrumentation instrumentation, MBeanServer server,
                                                               Set<ObjectName> names) {
        List<Map<String, Object>> components = new ArrayList<>();
        for (ObjectName name : names) {
            String domain = name.getDomain().toLowerCase(Locale.ROOT);
            if (!(domain.contains("catalina") || domain.contains("tomcat"))) continue;
            String type = componentType(name);
            if (type == null) continue;
            Map<String, Object> component = new LinkedHashMap<>();
            component.put("type", type);
            component.put("name", first(name, "name", "filterName", "servletName", "listenerName"));
            component.put("objectName", name.getCanonicalName());
            String className = attribute(server, name, "filterClass", "servletClass", "className", "managedResourceClass");
            if (className == null || className.isBlank()) className = attributeFromResource(server, name);
            component.put("className", className == null ? "unknown" : className);
            if (className != null) {
                Class<?> loaded = findUniqueLoaded(instrumentation, className);
                if (loaded != null) component.putAll(classFacts(instrumentation, loaded));
            }
            component.put("source", "jmx");
            components.add(component);
        }
        return components;
    }

    private static void collectContextPart(String collector, String context, DiagnosticLog diagnostics,
                                           CheckedCollector action) {
        try {
            diagnostics.ok(collector, context, action.collect());
        } catch (Throwable error) {
            diagnostics.partial(collector, context, List.of(describe(error)));
        }
    }

    private static Map<String, Object> component(Instrumentation instrumentation, String type, String name,
                                                  String className, String contextName, String source,
                                                  ClassLoader preferredLoader) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("type", type);
        item.put("name", name);
        item.put("className", className == null ? "unknown" : className);
        item.put("context", contextName);
        item.put("source", source);
        if (className != null) {
            Class<?> loaded = findLoaded(instrumentation, className, loaderId(preferredLoader));
            if (loaded != null) item.putAll(classFacts(instrumentation, loaded));
        }
        return item;
    }

    private static Map<String, Object> instanceComponent(Instrumentation instrumentation, String type, String name,
                                                         Object instance, String contextName, String source) {
        return classComponent(instrumentation, type, name, instance.getClass(), contextName, source);
    }

    private static Map<String, Object> classComponent(Instrumentation instrumentation, String type, String name,
                                                      Class<?> loaded, String contextName, String source) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("type", type);
        item.put("name", name);
        item.put("className", loaded.getName());
        item.put("context", contextName);
        item.put("source", source);
        item.putAll(classFacts(instrumentation, loaded));
        return item;
    }

    private static Object invoke(Object target, String method) throws Exception {
        if (target == null) throw new IllegalStateException(method + " target is null");
        Method value = target.getClass().getMethod(method);
        return value.invoke(target);
    }

    private static Object invoke(Object target, String method, Class<?>[] parameterTypes, Object... arguments) throws Exception {
        if (target == null) throw new IllegalStateException(method + " target is null");
        Method value = target.getClass().getMethod(method, parameterTypes);
        return value.invoke(target, arguments);
    }

    private static Object optionalInvoke(Object target, String method) {
        try {
            return invoke(target, method);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static List<Object> array(Object value) {
        if (value == null || !value.getClass().isArray()) return List.of();
        int length = java.lang.reflect.Array.getLength(value);
        List<Object> result = new ArrayList<>(length);
        for (int index = 0; index < length; index++) result.add(java.lang.reflect.Array.get(value, index));
        return result;
    }

    private static String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String componentType(ObjectName name) {
        String raw = String.join(" ", name.getKeyPropertyList().values()).toLowerCase(Locale.ROOT);
        if (raw.contains("filter")) return "filter";
        if (raw.contains("servlet") || raw.contains("wrapper")) return "servlet";
        if (raw.contains("listener")) return "listener";
        if (raw.contains("valve")) return "valve";
        return null;
    }

    private static String first(ObjectName name, String... keys) {
        for (String key : keys) {
            String value = name.getKeyProperty(key);
            if (value != null && !value.isBlank()) return value;
        }
        return name.getCanonicalName();
    }

    private static String attribute(MBeanServer server, ObjectName name, String... attributes) {
        for (String attribute : attributes) {
            try {
                Object value = server.getAttribute(name, attribute);
                if (value != null) return String.valueOf(value);
            } catch (Exception ignored) {
                // Tomcat versions expose different attribute names.
            }
        }
        return null;
    }

    private static String attributeFromResource(MBeanServer server, ObjectName name) {
        try {
            Object resource = server.invoke(name, "getManagedResource", new Object[0], new String[0]);
            return resource == null ? null : resource.getClass().getName();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Map<String, Object> inspectClass(Instrumentation instrumentation, String className, String classLoaderId) {
        List<Class<?>> matches = findLoadedClasses(instrumentation, className);
        Class<?> loaded = selectLoaded(matches, classLoaderId);
        if (loaded == null) {
            List<String> warnings = matches.isEmpty()
                    ? List.of("目标类未加载")
                    : List.of(classLoaderId == null ? "存在多个同名 Class，必须使用 classLoaderId 精确选择" : "指定 ClassLoader 中未找到目标类");
            return mapOf("className", className, "loaded", false, "candidateClassLoaderIds",
                    matches.stream().map(value -> loaderId(value.getClassLoader())).toList(),
                    "partial", true, "warnings", warnings);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("className", className);
        result.put("loaded", true);
        result.putAll(classFacts(instrumentation, loaded));
        result.put("partial", false);
        return result;
    }

    private static Map<String, Object> classFacts(Instrumentation instrumentation, Class<?> loaded) {
        Map<String, Object> facts = new LinkedHashMap<>();
        ClassLoader loader = loaded.getClassLoader();
        ProtectionDomain domain = loaded.getProtectionDomain();
        CodeSource source = domain == null ? null : domain.getCodeSource();
        URL location = source == null ? null : source.getLocation();
        ModuleDescriptor descriptor = loaded.getModule().getDescriptor();
        facts.put("classLoader", loader == null ? "bootstrap" : loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader)));
        facts.put("classLoaderId", loaderId(loader));
        facts.put("codeSource", location == null ? null : location.toString());
        facts.put("protectionDomain", domain == null ? null : domain.toString());
        facts.put("module", descriptor == null ? loaded.getModule().getName() : descriptor.name());
        facts.put("modifiable", instrumentation.isModifiableClass(loaded));
        return facts;
    }

    private static Map<String, Object> dumpClass(Instrumentation instrumentation, String className, String classLoaderId) throws Exception {
        List<Class<?>> matches = findLoadedClasses(instrumentation, className);
        Class<?> target = selectLoaded(matches, classLoaderId);
        if (target == null) {
            List<String> warnings = matches.isEmpty()
                    ? List.of("目标类未加载")
                    : List.of(classLoaderId == null ? "存在多个同名 Class，拒绝导出不确定对象" : "指定 ClassLoader 中未找到目标类");
            return mapOf("className", className, "candidateClassLoaderIds",
                    matches.stream().map(value -> loaderId(value.getClassLoader())).toList(),
                    "partial", true, "warnings", warnings);
        }
        if (!instrumentation.isRetransformClassesSupported() || !instrumentation.isModifiableClass(target)) {
            return mapOf("className", className, "partial", true, "warnings", List.of("目标 JVM 不支持该类的只读 retransformation capture"));
        }
        AtomicReference<byte[]> captured = new AtomicReference<>();
        ClassFileTransformer transformer = new ClassFileTransformer() {
            @Override
            public byte[] transform(Module module, ClassLoader loader, String name, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
                if (classBeingRedefined == target) captured.compareAndSet(null, classfileBuffer.clone());
                return null;
            }
        };
        instrumentation.addTransformer(transformer, true);
        try {
            instrumentation.retransformClasses(target);
        } finally {
            instrumentation.removeTransformer(transformer);
        }
        byte[] bytes = captured.get();
        if (bytes == null) return mapOf("className", className, "partial", true, "warnings", List.of("未捕获 Class 字节"));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("className", className);
        result.put("classLoaderId", loaderId(target.getClassLoader()));
        result.put("size", bytes.length);
        result.put("dataBase64", Base64.getEncoder().encodeToString(bytes));
        result.put("partial", false);
        return result;
    }

    private static List<Class<?>> findLoadedClasses(Instrumentation instrumentation, String className) {
        List<Class<?>> matches = new ArrayList<>();
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            if (loaded.getName().equals(className)) matches.add(loaded);
        }
        return matches;
    }

    private static Class<?> findUniqueLoaded(Instrumentation instrumentation, String className) {
        List<Class<?>> matches = findLoadedClasses(instrumentation, className);
        return matches.size() == 1 ? matches.get(0) : null;
    }

    private static Class<?> findLoaded(Instrumentation instrumentation, String className, String classLoaderId) {
        return selectLoaded(findLoadedClasses(instrumentation, className), classLoaderId);
    }

    private static Class<?> selectLoaded(List<Class<?>> matches, String classLoaderId) {
        if (classLoaderId == null) return matches.size() == 1 ? matches.get(0) : null;
        for (Class<?> loaded : matches) {
            if (loaderId(loaded.getClassLoader()).equals(classLoaderId)) return loaded;
        }
        return null;
    }

    private static String loaderId(ClassLoader loader) {
        return loader == null ? "bootstrap" : loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader));
    }

    private static String componentKey(Map<String, Object> component) {
        return String.join("\n",
                String.valueOf(component.get("type")),
                String.valueOf(component.get("context")),
                String.valueOf(component.get("container")),
                String.valueOf(component.get("name")),
                String.valueOf(component.get("className")),
                String.valueOf(component.get("classLoaderId")),
                String.valueOf(component.get("objectName")));
    }

    private static String describe(Throwable error) {
        Throwable cause = error.getCause() == null ? error : error.getCause();
        String message = cause.getMessage();
        return cause.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : ": " + message);
    }

    private static Map<String, Object> mapOf(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) result.put(String.valueOf(values[index]), values[index + 1]);
        return result;
    }

    @FunctionalInterface
    private interface CheckedCollector {
        int collect() throws Exception;
    }

    private static final class DiagnosticLog {
        private final List<Map<String, Object>> entries = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();
        private boolean partial;

        void ok(String collector, String context, int count) {
            Map<String, Object> entry = base(collector, context, "OK");
            entry.put("count", count);
            entries.add(entry);
        }

        void notPresent(String collector, String context, String message) {
            Map<String, Object> entry = base(collector, context, "NOT_PRESENT");
            entry.put("message", message);
            entries.add(entry);
        }

        void partial(String collector, String context, List<String> errors) {
            Map<String, Object> entry = base(collector, context, "PARTIAL");
            entry.put("errors", errors);
            entries.add(entry);
            partial = true;
            for (String error : errors) warnings.add(collector + (context == null ? "" : "[" + context + "]") + ": " + error);
        }

        void add(Map<String, Object> entry) {
            entries.add(entry);
        }

        List<Map<String, Object>> entries() {
            return List.copyOf(entries);
        }

        List<String> warnings() {
            return List.copyOf(warnings);
        }

        boolean partial() {
            return partial;
        }

        private static Map<String, Object> base(String collector, String context, String status) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("collector", collector);
            if (context != null) entry.put("context", context);
            entry.put("status", status);
            return entry;
        }
    }
}

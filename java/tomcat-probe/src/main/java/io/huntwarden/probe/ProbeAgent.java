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
        List<Map<String, Object>> components = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        components.addAll(listContextComponents(instrumentation, warnings));
        Set<String> componentKeys = new LinkedHashSet<>();
        for (Map<String, Object> item : components) componentKeys.add(item.get("type") + "\n" + item.get("name") + "\n" + item.get("className"));
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
            String key = component.get("type") + "\n" + component.get("name") + "\n" + component.get("className");
            if (componentKeys.add(key)) components.add(component);
        }
        components.sort(Comparator.comparing(value -> String.valueOf(value.get("type")) + value.get("name")));
        if (components.isEmpty()) warnings.add("Tomcat JMX 中未发现 Filter/Servlet/Listener MBean；容器可能关闭了相关注册或版本不兼容");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("components", components);
        result.put("warnings", warnings);
        result.put("partial", components.isEmpty());
        return result;
    }

    private static List<Map<String, Object>> listContextComponents(Instrumentation instrumentation, List<String> warnings) {
        List<Map<String, Object>> components = new ArrayList<>();
        Set<ClassLoader> loaders = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            ClassLoader loader = loaded.getClassLoader();
            if (loader != null && loader.getClass().getName().toLowerCase(Locale.ROOT).contains("webappclassloader")) loaders.add(loader);
        }
        for (ClassLoader loader : loaders) {
            try {
                Object resources = invoke(loader, "getResources");
                Object context = invoke(resources, "getContext");
                String contextName = String.valueOf(invoke(context, "getName"));
                for (Object filter : array(invoke(context, "findFilterDefs"))) {
                    String name = String.valueOf(invoke(filter, "getFilterName"));
                    String className = stringValue(invoke(filter, "getFilterClass"));
                    Object instance = optionalInvoke(filter, "getFilter");
                    if ((className == null || className.isBlank()) && instance != null) className = instance.getClass().getName();
                    components.add(component(instrumentation, "filter", name, className, contextName,
                            instance == null ? "descriptor" : "runtime-instance", loader));
                }
                for (Object wrapper : array(invoke(context, "findChildren"))) {
                    String name = String.valueOf(invoke(wrapper, "getName"));
                    String className = stringValue(optionalInvoke(wrapper, "getServletClass"));
                    if (className != null && !className.isBlank()) {
                        components.add(component(instrumentation, "servlet", name, className, contextName, "context-child", loader));
                    }
                }
                Set<String> listenerClasses = new LinkedHashSet<>();
                for (Object name : array(optionalInvoke(context, "findApplicationListeners"))) listenerClasses.add(String.valueOf(name));
                for (Object listener : array(optionalInvoke(context, "getApplicationEventListeners"))) {
                    if (listener != null) listenerClasses.add(listener.getClass().getName());
                }
                for (String className : listenerClasses) {
                    components.add(component(instrumentation, "listener", className, className, contextName, "runtime-context", loader));
                }
            } catch (Throwable error) {
                warnings.add("无法读取 Webapp ClassLoader 对应 Context: " + error.getClass().getSimpleName() + ": " + error.getMessage());
            }
        }
        return components;
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

    private static Object invoke(Object target, String method) throws Exception {
        if (target == null) throw new IllegalStateException(method + " target is null");
        Method value = target.getClass().getMethod(method);
        return value.invoke(target);
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

    private static Map<String, Object> mapOf(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) result.put(String.valueOf(values[index]), values[index + 1]);
        return result;
    }
}

package io.huntwarden.probe;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Read-only and bounded JVM, thread and Tomcat connector diagnostics. */
final class RuntimeDiagnostics {
    static final int MAX_ARGUMENTS = 256;
    static final int MAX_ARGUMENT_LENGTH = 1_024;
    static final int MAX_THREAD_STATE_SCAN = 4_096;
    static final int MAX_THREAD_SAMPLES = 256;
    static final int MAX_STACK_FRAMES = 8;
    static final int MAX_NETWORK_ITEMS = 64;

    private static final List<String> SENSITIVE_MARKERS = List.of(
            "password", "passwd", "secret", "token", "credential", "authorization",
            "cookie", "privatekey", "private_key", "apikey", "api_key", "accesskey", "access_key"
    );

    private RuntimeDiagnostics() {}

    record Section(String name, Map<String, Object> data, List<String> warnings, boolean partial) {
        Map<String, Object> collectorStatus() {
            Map<String, Object> status = new LinkedHashMap<>();
            status.put("collector", name);
            status.put("status", partial ? "PARTIAL" : "OK");
            status.put("warnings", warnings);
            return status;
        }
    }

    static Section collectJvm() {
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> warnings = new ArrayList<>();
        boolean partial = false;
        try {
            RuntimeMXBean bean = ManagementFactory.getRuntimeMXBean();
            result.put("pid", bean.getPid());
            result.put("runtimeName", bean.getName());
            result.put("vmName", bean.getVmName());
            result.put("vmVendor", bean.getVmVendor());
            result.put("vmVersion", bean.getVmVersion());
            result.put("specVersion", bean.getSpecVersion());
            result.put("startTimeMillis", bean.getStartTime());
            result.put("uptimeMillis", bean.getUptime());

            List<String> rawArguments = bean.getInputArguments();
            List<String> arguments = new ArrayList<>();
            List<Map<String, Object>> agents = new ArrayList<>();
            for (int index = 0; index < rawArguments.size() && index < MAX_ARGUMENTS; index++) {
                String raw = rawArguments.get(index);
                arguments.add(redactArgument(raw));
                Map<String, Object> agent = describeAgent(raw);
                if (agent != null) agents.add(agent);
            }
            boolean argumentsTruncated = rawArguments.size() > MAX_ARGUMENTS;
            if (argumentsTruncated) {
                warnings.add("JVM 参数超过采集上限 " + MAX_ARGUMENTS + "，已截断");
                partial = true;
            }
            result.put("inputArguments", arguments);
            result.put("inputArgumentsTruncated", argumentsTruncated);
            result.put("javaAgents", agents);

            Map<String, String> properties = bean.getSystemProperties();
            Map<String, Object> selectedProperties = new LinkedHashMap<>();
            for (String key : List.of("java.version", "java.vendor", "java.home", "java.io.tmpdir",
                    "java.class.path", "jdk.module.path", "java.library.path", "catalina.home", "catalina.base")) {
                String value = properties.get(key);
                if (value != null) selectedProperties.put(key, abbreviate(value, 4_096));
            }
            result.put("systemProperties", selectedProperties);
        } catch (Throwable error) {
            warnings.add("JVM 诊断采集失败: " + describe(error));
            partial = true;
        }
        return new Section("jvm_runtime", result, List.copyOf(warnings), partial);
    }

    static Section collectThreads() {
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> warnings = new ArrayList<>();
        boolean partial = false;
        try {
            ThreadMXBean bean = ManagementFactory.getThreadMXBean();
            result.put("threadCount", bean.getThreadCount());
            result.put("daemonThreadCount", bean.getDaemonThreadCount());
            result.put("peakThreadCount", bean.getPeakThreadCount());
            result.put("totalStartedThreadCount", bean.getTotalStartedThreadCount());

            long[] allIds = bean.getAllThreadIds();
            Arrays.sort(allIds);
            int stateScanCount = Math.min(allIds.length, MAX_THREAD_STATE_SCAN);
            long[] stateIds = Arrays.copyOf(allIds, stateScanCount);
            ThreadInfo[] stateInfos = bean.getThreadInfo(stateIds, 0);
            Map<Thread.State, Integer> stateCounts = new EnumMap<>(Thread.State.class);
            for (Thread.State state : Thread.State.values()) stateCounts.put(state, 0);
            for (ThreadInfo info : stateInfos) {
                if (info != null) stateCounts.compute(info.getThreadState(), (ignored, count) -> count == null ? 1 : count + 1);
            }
            Map<String, Object> namedStateCounts = new LinkedHashMap<>();
            for (Thread.State state : Thread.State.values()) namedStateCounts.put(state.name(), stateCounts.get(state));
            result.put("stateCounts", namedStateCounts);
            result.put("stateCountsSampled", stateScanCount);

            Map<Long, Thread> liveThreads = enumerateLiveThreads(warnings);
            int sampleCount = Math.min(allIds.length, MAX_THREAD_SAMPLES);
            long[] sampleIds = Arrays.copyOf(allIds, sampleCount);
            ThreadInfo[] sampleInfos = bean.getThreadInfo(sampleIds, MAX_STACK_FRAMES);
            List<Map<String, Object>> samples = new ArrayList<>();
            for (ThreadInfo info : sampleInfos) {
                if (info == null) continue;
                Map<String, Object> sample = new LinkedHashMap<>();
                sample.put("threadId", info.getThreadId());
                sample.put("name", abbreviate(info.getThreadName(), 512));
                sample.put("state", info.getThreadState().name());
                sample.put("lockName", info.getLockName());
                sample.put("lockOwnerId", info.getLockOwnerId());
                Thread thread = liveThreads.get(info.getThreadId());
                if (thread != null) {
                    sample.put("daemon", thread.isDaemon());
                    try {
                        ClassLoader loader = thread.getContextClassLoader();
                        sample.put("contextClassLoader", loader == null ? "bootstrap" : loader.getClass().getName());
                        sample.put("contextClassLoaderId", loaderId(loader));
                    } catch (SecurityException error) {
                        warnings.add("无法读取线程 " + info.getThreadId() + " 的 ContextClassLoader: " + describe(error));
                        partial = true;
                    }
                }
                List<String> stack = new ArrayList<>();
                for (StackTraceElement frame : info.getStackTrace()) stack.add(formatFrame(frame));
                sample.put("stack", stack);
                samples.add(sample);
            }
            boolean truncated = allIds.length > MAX_THREAD_SAMPLES || allIds.length > MAX_THREAD_STATE_SCAN;
            if (truncated) {
                warnings.add("JVM 线程超过诊断摘要上限，线程样本或状态统计已截断");
                partial = true;
            }
            result.put("sampledThreads", samples);
            result.put("sampleLimit", MAX_THREAD_SAMPLES);
            result.put("truncated", truncated);
        } catch (Throwable error) {
            warnings.add("线程诊断采集失败: " + describe(error));
            partial = true;
        }
        return new Section("jvm_threads", result, deduplicate(warnings), partial);
    }

    static Section collectNetwork(MBeanServer server, Set<ObjectName> objectNames) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> warnings = new ArrayList<>();
        List<Map<String, Object>> listeners = new ArrayList<>();
        List<Map<String, Object>> metrics = new ArrayList<>();
        boolean partial = false;
        try {
            List<ObjectName> sorted = objectNames.stream()
                    .sorted(Comparator.comparing(ObjectName::getCanonicalName))
                    .toList();
            for (ObjectName objectName : sorted) {
                String domain = objectName.getDomain().toLowerCase(Locale.ROOT);
                if (!(domain.contains("catalina") || domain.contains("tomcat"))) continue;
                String type = String.valueOf(objectName.getKeyProperty("type")).toLowerCase(Locale.ROOT);
                if (type.equals("threadpool") || type.equals("protocolhandler") || type.equals("connector")) {
                    if (listeners.size() >= MAX_NETWORK_ITEMS) {
                        partial = true;
                        continue;
                    }
                    listeners.add(networkItem(server, objectName, List.of(
                            "address", "port", "localPort", "protocol", "executor", "maxThreads",
                            "currentThreadCount", "currentThreadsBusy", "maxConnections", "connectionCount",
                            "keepAliveCount", "acceptCount"
                    )));
                } else if (type.equals("globalrequestprocessor")) {
                    if (metrics.size() >= MAX_NETWORK_ITEMS) {
                        partial = true;
                        continue;
                    }
                    metrics.add(networkItem(server, objectName, List.of(
                            "requestCount", "errorCount", "bytesReceived", "bytesSent", "processingTime", "maxTime"
                    )));
                }
            }
            if (partial) warnings.add("Tomcat 连接器或请求指标超过每类 " + MAX_NETWORK_ITEMS + " 项，已截断");
        } catch (Throwable error) {
            warnings.add("Tomcat 网络诊断采集失败: " + describe(error));
            partial = true;
        }
        result.put("listeners", listeners);
        result.put("requestMetrics", metrics);
        result.put("listenerCount", listeners.size());
        result.put("requestMetricCount", metrics.size());
        result.put("scope", "Tomcat JMX connector summary; not an operating-system socket table");
        return new Section("tomcat_network", result, List.copyOf(warnings), partial);
    }

    static String redactArgument(String argument) {
        String value = argument == null ? "" : argument;
        String lower = value.toLowerCase(Locale.ROOT);
        boolean sensitive = SENSITIVE_MARKERS.stream().anyMatch(lower::contains);
        if (sensitive) {
            int separator = value.indexOf('=');
            if (separator >= 0) value = value.substring(0, separator + 1) + "[REDACTED]";
            else value = "[REDACTED_JVM_ARGUMENT]";
        }
        return abbreviate(value, MAX_ARGUMENT_LENGTH);
    }

    private static Map<String, Object> describeAgent(String argument) {
        String kind;
        String value;
        if (argument.startsWith("-javaagent:")) {
            kind = "javaagent";
            value = argument.substring("-javaagent:".length());
        } else if (argument.startsWith("-agentpath:")) {
            kind = "agentpath";
            value = argument.substring("-agentpath:".length());
        } else if (argument.startsWith("-agentlib:")) {
            kind = "agentlib";
            value = argument.substring("-agentlib:".length());
        } else {
            return null;
        }
        int options = value.indexOf('=');
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("kind", kind);
        result.put("location", abbreviate(options < 0 ? value : value.substring(0, options), 2_048));
        result.put("optionsPresent", options >= 0 && options < value.length() - 1);
        return result;
    }

    private static Map<String, Object> networkItem(MBeanServer server, ObjectName name, List<String> attributes) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("name", name.getKeyProperty("name"));
        item.put("type", name.getKeyProperty("type"));
        item.put("objectName", name.getCanonicalName());
        for (String attribute : attributes) {
            Object value = attribute(server, name, attribute);
            if (value != null) item.put(attribute, scalar(value));
        }
        return item;
    }

    private static Object attribute(MBeanServer server, ObjectName name, String attribute) {
        try {
            return server.getAttribute(name, attribute);
        } catch (Exception ignored) {
            // Attribute names differ between Tomcat branches; unsupported optional fields are omitted.
            return null;
        }
    }

    private static Object scalar(Object value) {
        if (value instanceof Number || value instanceof Boolean) return value;
        return abbreviate(String.valueOf(value), 2_048);
    }

    private static Map<Long, Thread> enumerateLiveThreads(List<String> warnings) {
        Map<Long, Thread> result = new HashMap<>();
        ThreadGroup root = Thread.currentThread().getThreadGroup();
        while (root.getParent() != null) root = root.getParent();
        int capacity = Math.max(64, Math.min(MAX_THREAD_STATE_SCAN, root.activeCount() * 2 + 32));
        Thread[] threads = new Thread[capacity];
        int count = root.enumerate(threads, true);
        if (count >= capacity) warnings.add("活动线程枚举达到上限，部分 ContextClassLoader 关联可能缺失");
        for (int index = 0; index < count && index < threads.length; index++) {
            Thread thread = threads[index];
            if (thread != null) result.put(thread.getId(), thread);
        }
        return result;
    }

    private static String formatFrame(StackTraceElement frame) {
        String source = frame.getFileName() == null ? "Unknown Source" : frame.getFileName();
        if (frame.getLineNumber() >= 0) source += ":" + frame.getLineNumber();
        return frame.getClassName() + "#" + frame.getMethodName() + "(" + source + ")";
    }

    private static String loaderId(ClassLoader loader) {
        return loader == null ? "bootstrap"
                : loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader));
    }

    private static String abbreviate(String value, int limit) {
        if (value == null || value.length() <= limit) return value;
        return value.substring(0, limit) + "…[truncated]";
    }

    private static List<String> deduplicate(List<String> values) {
        return values.stream().distinct().toList();
    }

    private static String describe(Throwable error) {
        Throwable cause = error.getCause() == null ? error : error.getCause();
        String message = cause.getMessage();
        return cause.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : ": " + message);
    }
}

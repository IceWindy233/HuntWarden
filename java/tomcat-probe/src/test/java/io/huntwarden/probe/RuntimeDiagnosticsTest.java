package io.huntwarden.probe;

import org.junit.jupiter.api.Test;

import java.lang.management.ManagementFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuntimeDiagnosticsTest {
    @Test
    void redactsSensitiveJvmArgumentValues() {
        assertEquals("-Ddatabase.password=[REDACTED]",
                RuntimeDiagnostics.redactArgument("-Ddatabase.password=do-not-leak"));
        assertEquals("[REDACTED_JVM_ARGUMENT]",
                RuntimeDiagnostics.redactArgument("--access-token do-not-leak"));
        assertEquals("-XX:+HeapDumpOnOutOfMemoryError",
                RuntimeDiagnostics.redactArgument("-XX:+HeapDumpOnOutOfMemoryError"));
    }

    @Test
    void collectsBoundedJvmAndThreadSummaries() {
        RuntimeDiagnostics.Section jvm = RuntimeDiagnostics.collectJvm();
        RuntimeDiagnostics.Section threads = RuntimeDiagnostics.collectThreads();

        assertNotNull(jvm.data().get("pid"));
        assertTrue(jvm.data().containsKey("inputArguments"));
        assertTrue(jvm.data().containsKey("javaAgents"));
        assertNotNull(threads.data().get("threadCount"));
        assertTrue(threads.data().containsKey("stateCounts"));
        assertTrue(threads.data().containsKey("sampledThreads"));
    }

    @Test
    void describesNetworkScopeWithoutClaimingOsSocketCoverage() {
        RuntimeDiagnostics.Section network = RuntimeDiagnostics.collectNetwork(
                ManagementFactory.getPlatformMBeanServer(),
                ManagementFactory.getPlatformMBeanServer().queryNames(null, null));

        assertEquals("Tomcat JMX connector summary; not an operating-system socket table",
                network.data().get("scope"));
        assertTrue(network.data().containsKey("listeners"));
        assertTrue(network.data().containsKey("requestMetrics"));
        assertFalse(network.partial());
    }
}

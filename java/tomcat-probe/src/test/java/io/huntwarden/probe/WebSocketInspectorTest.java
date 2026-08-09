package io.huntwarden.probe;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class WebSocketInspectorTest {
    @Test
    void discoversEndpointConfigThroughTomcatStylePrivateMappingWrappers() {
        FakeWsServerContainer container = new FakeWsServerContainer();
        container.configExactMatchMap.put("/ignored-map-key",
                new FakePathMatch(new FakeServerEndpointConfig("/socket/{id}", ExampleEndpoint.class)));

        WebSocketInspector.ScanResult result = WebSocketInspector.inspect(container);

        assertEquals(1, result.endpoints().size());
        assertEquals("/socket/{id}", result.endpoints().get(0).path());
        assertEquals(ExampleEndpoint.class, result.endpoints().get(0).endpointClass());
        assertEquals(0, result.reflectionErrors().size());
        assertFalse(result.truncated());
    }

    @Test
    void terminatesOnCyclesWithoutDuplicatingEndpoints() {
        FakeWsServerContainer container = new FakeWsServerContainer();
        container.configExactMatchMap.put("self", container);
        FakeServerEndpointConfig config = new FakeServerEndpointConfig("/events", ExampleEndpoint.class);
        container.configExactMatchMap.put("one", config);
        container.configExactMatchMap.put("two", config);

        WebSocketInspector.ScanResult result = WebSocketInspector.inspect(container);

        assertEquals(1, result.endpoints().size());
        assertFalse(result.truncated());
    }

    static final class FakeWsServerContainer {
        private final Map<String, Object> configExactMatchMap = new LinkedHashMap<>();
    }

    static final class FakePathMatch {
        private final Object config;

        FakePathMatch(Object config) {
            this.config = config;
        }
    }

    static final class FakeServerEndpointConfig {
        private final String path;
        private final Class<?> endpointClass;

        FakeServerEndpointConfig(String path, Class<?> endpointClass) {
            this.path = path;
            this.endpointClass = endpointClass;
        }

        public String getPath() {
            return path;
        }

        public Class<?> getEndpointClass() {
            return endpointClass;
        }
    }

    static final class ExampleEndpoint {}
}

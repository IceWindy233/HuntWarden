package io.huntwarden.probe;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JsonTest {
    @Test
    void serializesWithoutExternalRuntimeDependencies() {
        LinkedHashMap<String, Object> value = new LinkedHashMap<>();
        value.put("ok", true);
        value.put("items", List.of("a\nb"));
        assertEquals("{\"ok\":true,\"items\":[\"a\\nb\"]}", Json.stringify(value));
    }
}

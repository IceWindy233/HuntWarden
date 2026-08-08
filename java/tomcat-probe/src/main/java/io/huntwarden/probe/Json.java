package io.huntwarden.probe;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

final class Json {
    private Json() {}

    static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        append(out, value);
        return out.toString();
    }

    private static void append(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String || value instanceof Character) {
            quote(out, String.valueOf(value));
        } else if (value instanceof Number || value instanceof Boolean) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            Iterator<? extends Map.Entry<?, ?>> iterator = map.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<?, ?> entry = iterator.next();
                quote(out, String.valueOf(entry.getKey()));
                out.append(':');
                append(out, entry.getValue());
                if (iterator.hasNext()) out.append(',');
            }
            out.append('}');
        } else if (value instanceof Collection<?> collection) {
            out.append('[');
            Iterator<?> iterator = collection.iterator();
            while (iterator.hasNext()) {
                append(out, iterator.next());
                if (iterator.hasNext()) out.append(',');
            }
            out.append(']');
        } else if (value.getClass().isArray()) {
            out.append('[');
            for (int index = 0; index < Array.getLength(value); index++) {
                if (index > 0) out.append(',');
                append(out, Array.get(value, index));
            }
            out.append(']');
        } else {
            quote(out, String.valueOf(value));
        }
    }

    private static void quote(StringBuilder out, String value) {
        out.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (character < 0x20) out.append(String.format("\\u%04x", (int) character));
                    else out.append(character);
                }
            }
        }
        out.append('"');
    }
}

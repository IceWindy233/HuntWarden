package fixture.websocket;

public final class EndpointFixtures {
    private EndpointFixtures() {}

    public static Object packagePrivateConfig(String path, Class<?> endpointClass) {
        return new PackagePrivateConfig(path, endpointClass);
    }

    private static final class PackagePrivateConfig {
        private final String path;
        private final Class<?> endpointClass;

        private PackagePrivateConfig(String path, Class<?> endpointClass) {
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
}

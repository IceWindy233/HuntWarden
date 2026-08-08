package lab;

import javax.servlet.*;
import java.util.EnumSet;

public final class LabInitializer implements ServletContainerInitializer {
    @Override
    public void onStartup(java.util.Set<Class<?>> classes, ServletContext context) {
        FilterRegistration.Dynamic registration = context.addFilter("huntwardenDynamicMarker", new DynamicMarkerFilter());
        registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, "/*");
    }
}

package lab;

import javax.servlet.*;
import java.util.EnumSet;

public final class LabBootstrapListener implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent event) {
        FilterRegistration.Dynamic registration = event.getServletContext().addFilter("huntwardenDynamicMarker", new DynamicMarkerFilter());
        registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, "/*");
    }
}

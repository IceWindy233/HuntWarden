package lab;

import javax.servlet.*;
import java.io.IOException;

public final class DynamicMarkerFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (response instanceof javax.servlet.http.HttpServletResponse http) http.setHeader("X-HuntWarden-Lab", "dynamic-filter");
        chain.doFilter(request, response);
    }
}

package lab;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Minimal real Spring MVC graph used by the read-only runtime discovery acceptance test. */
@Configuration
@EnableWebMvc
public class LabSpringConfig implements WebMvcConfigurer {
    @Bean
    public LabSpringController labSpringController() {
        return new LabSpringController();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new LabSpringInterceptor());
    }
}

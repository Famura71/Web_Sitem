package Server;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/Server/");
        registry.addResourceHandler("/Photos/**")
                .addResourceLocations("classpath:/Photos/");
        registry.addResourceHandler("/PDFs/**")
                .addResourceLocations(
                        "file:src/main/resources/PDFs/",
                        "classpath:/PDFs/"
                );
    }
}

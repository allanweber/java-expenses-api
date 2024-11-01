package com.allanweber.expenses.configuration.api;

import com.allanweber.expenses.authentication.token.AccessTokenResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
public class WebConfigArgumentResolvers implements WebMvcConfigurer {

    private final AccessTokenResolver accessTokenResolver;

    public WebConfigArgumentResolvers(AccessTokenResolver accessTokenResolver) {
        this.accessTokenResolver = accessTokenResolver;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(accessTokenResolver);
    }
}

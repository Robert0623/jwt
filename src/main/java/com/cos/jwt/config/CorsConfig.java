package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true); // 서버가 응답을 할 때 json을 js에서 처리할 수 있게 할지를 설정하는 것
        // config.setAllowedOrigins(List.of("https://www.aaa.com"));
        config.addAllowedOriginPattern("*"); // 모든 ip에 응답을 허용하겠다.
        config.addAllowedHeader("*"); // 모든 header에 응답을 허용하겠다.
        config.addAllowedMethod("*"); // 모든 post,get,put,delete,patch 요청을 허용하겠다.

        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
package com.cos.jwt.config;

import com.cos.jwt.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

        return http
                // .addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class)
                .csrf(c -> c
                        .disable())
                .sessionManagement(s -> s
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsFilter) // @CrossOrigin(인증 X) -> Controller에 사용, addFilter(인증 O) -> 시큐리티 필터에 등록
                .addFilter(new JwtAuthenticationFilter(authenticationManager)) // AuthenticationManager
                .formLogin(f -> f
                        .disable())
                .httpBasic(h -> h
                        .disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/user/**")
                        .hasAnyRole("USER", "MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/manager/**")
                        .hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/admin/**")
                        .hasRole("ADMIN")
                        .anyRequest().permitAll())
                .build();
    }

}
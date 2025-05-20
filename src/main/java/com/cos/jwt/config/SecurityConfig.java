package com.cos.jwt.config;

import com.cos.jwt.UserRepository;
import com.cos.jwt.jwt.JwtAuthenticationFilter;
import com.cos.jwt.jwt.JwtAuthorizationFilter;
import com.cos.jwt.jwt.JwtProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        return http
                // .addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class)
                .csrf(c -> c
                        .disable())
                .sessionManagement(s -> s
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsFilter) // @CrossOrigin(인증 X) -> Controller에 사용, addFilter(인증 O) -> 시큐리티 필터에 등록
                .addFilter(new JwtAuthenticationFilter(authenticationManager, objectMapper, jwtProperties)) // AuthenticationManager
                .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository, jwtProperties))
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
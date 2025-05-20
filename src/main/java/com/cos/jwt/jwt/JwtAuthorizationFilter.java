package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.UserRepository;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

/**
 *  시큐리티가 Filter를 가지고 있는데 그 Filter 중에 BasicAuthenticationFilter가 있음
 *  권한 or 인증이 필요한 특정 url을 요청했을 때 위 Filter를 무조건 타게 되어있음
 *  만약 권한이 인증에 필요한 url이 아니라면 이 필터를 안탐
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, JwtProperties jwtProperties) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.jwtProperties = jwtProperties;
    }

    // 권한 or 인증이 필요한 주소 요청이 있을 때 해당 필터를 탐
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("권한이나 인증이 필요한 주소 요청이 됨.");

        String jwtHeader = request.getHeader(jwtProperties.getHeaderString());
        System.out.println("jwtHeader = " + jwtHeader);

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith(jwtProperties.getTokenPrefix())) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader(jwtProperties.getHeaderString()).replace(jwtProperties.getTokenPrefix() + " ", "");
        String username = JWT
                .require(Algorithm.HMAC512(jwtProperties.getSecretKey()))
                .build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();

        if (username != null || !username.isBlank()) {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("ID 또는 PASSWORD를 찾을 수 없습니다."));

            PrincipalDetails principalDetails = new PrincipalDetails(user);

            // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principalDetails,
                    null,
                    principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }

    }
}

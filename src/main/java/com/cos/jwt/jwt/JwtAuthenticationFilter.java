package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.request.Signin;
import com.cos.jwt.response.SigninResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음.
// formLogin에서는 POST /login 요청해서 username, password 전송하면
// UsernamePasswordAuthenticationFilter 동작을 함.
// formLogin(f -> f.disable())에서는 시큐리티 필터에 다시 등록해줘야 함!
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;
    private final JwtProperties jwtProperties;

    // POST /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println(">>>>>>>>>>>>>attemptAuthentication");
        // 1. username, password 받아서
        try {
            Signin userInfo = objectMapper.readValue(request.getInputStream(), Signin.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userInfo.getUsername(), userInfo.getPassword());

            // 2. 정상인지 로그인 시도 --> authenticationManager로 로그인 시도를 하면
            //    PrincipalDetailsService가 호출 --> loadUserByUsername() 함수 실행
            //    --> db에서 username으로 유저정보를 가져와서 리턴
            //    --> 정상이면 PrincipalDetails가 포함된 authentication 객체 리턴
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 4. return authentication --> 객체를 SecurityContextHolder에 임시로 저장
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** attemptAuthentication 실행 후 인증이 정상적으로 되면 --> successfulAuthentication 함수가 실행 됨
     * JWT 토큰을 만들어서 request요청한 사용자에게 JWT 토큰을 response 해주면 됨
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        List<String> roles = principalDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        /**
         *  username, password --> 로그인 정상 --> JWT 토큰을 생성 --> Client로 JWT 토큰을 응답
         *  요청할 때 마다 JWT토큰을 가지고 요청
         *  서버는 JWT토큰이 유효한지를 판단 (필터 필요)
         */
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUserId().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + jwtProperties.getExpirationTime()))
                .withClaim("username", principalDetails.getUsername())
                .withClaim("roles", roles)
                .sign(Algorithm.HMAC512(jwtProperties.getSecretKey()));

        response.addHeader(jwtProperties.getHeaderString(), jwtProperties.getTokenPrefix() + " " + jwtToken);

        SigninResponse userInfo = SigninResponse.builder()
                .id(principalDetails.getUserId())
                .username(principalDetails.getUsername())
                .roles(roles)
                .message("로그인 성공")
                .accessToken(jwtToken)
                .tokenType(jwtProperties.getTokenPrefix())
                .expiresMilliSeconds(jwtProperties.getExpirationTime())
                .build();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");

        objectMapper.writeValue(response.getWriter(), userInfo);
    }
}

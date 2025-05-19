package com.cos.jwt.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음.
// formLogin에서는 POST /login 요청해서 username, password 전송하면
// UsernamePasswordAuthenticationFilter 동작을 함.
// formLogin(f -> f.disable())에서는 시큐리티 필터에 다시 등록해줘야 함!
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // POST /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println(">>>>>>>>>>>>>attemptAuthentication");
        // 1. username, password 받아서

        // 2. 정상인지 로그인 시도 --> authenticationManager로 로그인 시도를 하면 
        // PrincipalDetailsService가 호출 --> loadUserByUsername() 함수 실행
        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해 필요. 권한관리가 필요없으면 사용할 필요 없음) 
        // 4. jwt 토큰을 만들어서 응답해주면 됨


        return super.attemptAuthentication(request, response);
    }
}

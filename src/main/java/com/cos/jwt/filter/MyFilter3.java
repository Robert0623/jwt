package com.cos.jwt.filter;

import jakarta.servlet.*;

import java.io.IOException;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터3");
        chain.doFilter(request, response);
    }
}

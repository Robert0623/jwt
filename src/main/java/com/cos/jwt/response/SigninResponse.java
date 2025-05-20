package com.cos.jwt.response;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
public class SigninResponse {

    private Long id;
    private String username;
    private List<String> roles;

    private String message;
    private String accessToken;
    private String tokenType;
    private long expiresMilliSeconds;

    @Builder
    public SigninResponse(Long id, String username, List<String> roles, String message, String accessToken, String tokenType, long expiresMilliSeconds) {
        this.id = id;
        this.username = username;
        this.roles = roles;
        this.message = message;
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresMilliSeconds = expiresMilliSeconds;
    }
}

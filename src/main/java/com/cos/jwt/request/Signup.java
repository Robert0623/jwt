package com.cos.jwt.request;

import com.cos.jwt.model.User;
import lombok.Getter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Getter
public class Signup {

    private String username;
    private String password;

    public User toEntity(BCryptPasswordEncoder bCryptPasswordEncoder) {
        return User.builder()
                .username(this.username)
                .password(bCryptPasswordEncoder.encode(this.getPassword()))
                .roles("ROLE_USER")
                .build();
    }
}
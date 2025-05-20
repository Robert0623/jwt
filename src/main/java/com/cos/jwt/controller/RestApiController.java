package com.cos.jwt.controller;

import com.cos.jwt.UserRepository;
import com.cos.jwt.model.User;
import com.cos.jwt.request.Signup;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("/signup")
    public String signup(@RequestBody Signup request) {
        User user = request.toEntity(bCryptPasswordEncoder);
        userRepository.save(user);

        return "회원가입 성공";
    }
}

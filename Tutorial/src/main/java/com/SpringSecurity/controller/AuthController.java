package com.SpringSecurity.controller;

import com.SpringSecurity.Service.AuthService;
import com.SpringSecurity.dto.AuthResponse;
import com.SpringSecurity.dto.LoginRequest;
import com.SpringSecurity.dto.RefreshTokenRequest;
import com.SpringSecurity.dto.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request){
        return authService.register(request);
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest request){
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request);
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request){
        return authService.logout(request);
    }

}

package com.SpringSecurity.controller;

import com.SpringSecurity.Service.AuthService;
import com.SpringSecurity.dto.UserResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/public")
public class PublicUserController {

    private final AuthService authService;

    public PublicUserController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/users")
    public List<UserResponse> getAllUsers(){
        return authService.getPublicUsers();
    }
}

package com.SpringSecurity.security;

import com.SpringSecurity.entity.User;
import com.SpringSecurity.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;



    public OAuth2LoginSuccessHandler(UserRepository userRepository, JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        OAuth2User oAuth2User=(OAuth2User)  authentication.getPrincipal();
        String email=oAuth2User.getAttribute("email");

        User user=userRepository.findByUsername(email)
                .orElseGet(()->{
                    User newUser=new User();
                    newUser.setUsername(email);
                    newUser.setRole("ROLE_USER");
                    newUser.setProvider("GOOGLE");

                    newUser.setPassword(
                            passwordEncoder.encode("OAUTH2_USER")
                    );
                    return userRepository.save(newUser);
                });


        String token=jwtUtil.generateAccessToken(user.getUsername());

        response.sendRedirect(
                "http://localhost:8080/dashboard.html?token="+token
        );
    }
}

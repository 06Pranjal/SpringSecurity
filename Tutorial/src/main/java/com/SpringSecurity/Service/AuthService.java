package com.SpringSecurity.Service;

import com.SpringSecurity.dto.*;
import com.SpringSecurity.entity.User;
import com.SpringSecurity.repository.UserRepository;
import com.SpringSecurity.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthService {
    private final UserRepository repository;

    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;


    public AuthService(UserRepository repository,
                       JwtUtil jwtUtil,
                       PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    public String register(RegisterRequest request){
        User user=new User();

        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());

        repository.save(user);
        return "User Registered Successfully";

    }

    public AuthResponse login(LoginRequest request){
        User user=repository.findByUsername(request.getUsername())
                .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"User not Found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        String accessToken=jwtUtil.generateAccessToken(user.getUsername());
        String refreshToken=jwtUtil.generateRefreshToken(user.getUsername());

        user.setRefreshToken(refreshToken);
        repository.save(user);

        return new AuthResponse(accessToken,refreshToken);

    }
// PUBLIC APIs to get only ROLE_USERS
    public List<UserResponse> getPublicUsers() {
        return repository.findAll()
                .stream()
                .filter(user->"ROLE_USER".equals(user.getRole()))
                .map(user->new UserResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getRole()
                ))
                .collect(Collectors.toList());
    }

    //APIs to get all users
    public List<UserResponse> getAllUsersForAdmin(){
        return repository.findAll()
                .stream()
                .map(user->new UserResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getRole()
                ))
                .collect(Collectors.toList());

    }

//    public String refreshAccessToken(String refreshToken) {
//
//        if (!jwtUtil.isTokenValid(refreshToken)) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
//        }
//
//        String username = jwtUtil.extractUsername(refreshToken);
//        return jwtUtil.generateAccessToken(username);
//    }


    public AuthResponse refreshToken(RefreshTokenRequest request) {

        // 1️⃣ Extract username from refresh token
        String username = jwtUtil.extractUsername(request.getRefreshToken());

        // 2️⃣ Fetch user from DB
        User user = repository.findByUsername(username)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        // 3️⃣ Compare DB refresh token
        if (!request.getRefreshToken().equals(user.getRefreshToken())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token mismatch");
        }

        // 4️⃣ Generate new access token
        String newAccessToken = jwtUtil.generateAccessToken(username);

        return new AuthResponse(newAccessToken, request.getRefreshToken());
    }


    public String logout(HttpServletRequest request) {
        String authHeader=request.getHeader("Authorization");

        if(authHeader==null || !authHeader.startsWith("Bearer ")){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"No Token Found");
        }

        String token=authHeader.substring(7);
        String username=jwtUtil.extractUsername(token);

        User user=repository.findByUsername(username)
                .orElseThrow(()->new ResponseStatusException((HttpStatus.NOT_FOUND)));

        user.setRefreshToken(null);
        repository.save(user);

        return "Logged out successfully";
    }
}

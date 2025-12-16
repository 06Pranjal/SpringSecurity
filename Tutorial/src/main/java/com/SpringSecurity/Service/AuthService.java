package com.SpringSecurity.Service;

import com.SpringSecurity.dto.LoginRequest;
import com.SpringSecurity.dto.RegisterRequest;
import com.SpringSecurity.dto.UserResponse;
import com.SpringSecurity.entity.User;
import com.SpringSecurity.repository.UserRepository;
import com.SpringSecurity.security.JwtUtil;
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

    public String login(LoginRequest request){
        User user=repository.findByUsername(request.getUsername())
                .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"User not Found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Invalid password");
        }

        return jwtUtil.generateToken(user.getUsername());

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

}

package com.SpringSecurity.Service;

import com.SpringSecurity.dto.LoginRequest;
import com.SpringSecurity.dto.RegisterRequest;
import com.SpringSecurity.dto.UserResponse;
import com.SpringSecurity.entity.User;
import com.SpringSecurity.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthService {
    private final UserRepository repository;

    public AuthService(UserRepository repository) {
        this.repository = repository;
    }

    public String register(RegisterRequest request){
        User user=new User();

        user.setUsername(request.getUsername());
        user.setPassword(request.getPassword());
        user.setRole(request.getRole());

        repository.save(user);
        return "User Registered Successfully";

    }

    public String login(LoginRequest request){
        User user=repository.findByUsername(request.getUsername())
                .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"User not Found"));

        if(!user.getPassword().equals(request.getPassword())){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid Password");
        }

        return "Login Successful for user: "+user.getUsername();

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

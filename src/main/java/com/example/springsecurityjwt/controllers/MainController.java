package com.example.springsecurityjwt.controllers;

import com.example.springsecurityjwt.dto.CreateUserDTO;
import com.example.springsecurityjwt.models.ERole;
import com.example.springsecurityjwt.models.RoleEntity;
import com.example.springsecurityjwt.models.UserEntity;
import com.example.springsecurityjwt.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class MainController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/hello")
    public String hello(){
        return "Hello World not secured";
    }

    @GetMapping("/hello-secured")
    public String helloSecured() {
        return "Hello World secured";
    }

    @PostMapping("/create-user")
    public ResponseEntity<?> createUser(
            @Valid @RequestBody CreateUserDTO createUserDTO
    ){
        Set<RoleEntity> roles = createUserDTO.getRoles()
                .stream()
                .map(role ->
                        RoleEntity.builder()
                                .name(ERole.valueOf(role))
                                .build()
                )
                .collect(Collectors.toSet());

        UserEntity userEntity = UserEntity.builder()
                .username(createUserDTO.getUsername())
                .password(passwordEncoder.encode(createUserDTO.getPassword()))
                .email(createUserDTO.getEmail())
                .roles(roles)
                .build();

        UserEntity userCreated = userRepository.save(userEntity);

        return ResponseEntity.ok(userCreated);
    }

    @DeleteMapping("/delete-user/{id}")
    public String deleteUser(
            @PathVariable("id") Long id
    ){
        userRepository.deleteById(id);
        return "User deleted with id: " + id;
    }
}

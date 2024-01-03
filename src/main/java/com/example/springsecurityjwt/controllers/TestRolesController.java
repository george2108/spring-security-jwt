package com.example.springsecurityjwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestRolesController {
    @GetMapping("/admin")
    // Validamos que el usuario tenga el rol de ADMIN
    // para habilitar esta validacion hay que habilitar la seguridad a nivel de metodo en SecurityConfig.java
    @PreAuthorize("hasRole('ADMIN')")
    public String accessAdmin(){
        return "Hello admin";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String accessUser(){
        return "Hello user";
    }

    @GetMapping("/guest")
    @PreAuthorize("hasRole('GUEST')")
    public String accessGuest(){
        return "Hello guest";
    }
}

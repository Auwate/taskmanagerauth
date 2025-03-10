package com.example.taskmanagerauth.service;

import org.springframework.security.crypto.password.PasswordEncoder;

public class DefaultPasswordEncodingService implements PasswordEncodingService {

    private final PasswordEncoder passwordEncoder;

    public DefaultPasswordEncodingService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public String encode(String password) {
        return passwordEncoder.encode(password);
    }

    public PasswordEncoder getEncoder() {
        return passwordEncoder;
    }

}

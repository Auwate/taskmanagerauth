package com.example.taskmanagerauth.service;

import org.springframework.security.crypto.password.PasswordEncoder;

public interface PasswordEncodingService {
    String encode(String password);
    PasswordEncoder getEncoder();
}

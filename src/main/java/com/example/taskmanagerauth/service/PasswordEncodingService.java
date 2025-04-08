package com.example.taskmanagerauth.service;

import org.springframework.security.crypto.password.PasswordEncoder;

public interface PasswordEncodingService {
    String encode(String password);
    Boolean matches(String rawPassword, String encoded);
    PasswordEncoder getEncoder();
}

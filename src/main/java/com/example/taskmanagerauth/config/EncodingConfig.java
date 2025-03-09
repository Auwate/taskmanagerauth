package com.example.taskmanagerauth.config;

import com.example.taskmanagerauth.service.DefaultPasswordEncodingService;
import com.example.taskmanagerauth.service.PasswordEncodingService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class EncodingConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PasswordEncodingService passwordEncoderService() {
        return new DefaultPasswordEncodingService(passwordEncoder());
    }

}

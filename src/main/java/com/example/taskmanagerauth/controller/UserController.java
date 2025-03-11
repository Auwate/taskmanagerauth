package com.example.taskmanagerauth.controller;

import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.service.UserService;
import com.example.taskmanagerauth.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/auth/register")
    public ResponseEntity<ApiResponse<Void>> register(@RequestBody User user) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to register...");
        }

        logger.info("POST HTTP request received at /api/auth/register");

        userService.registerUser(user);

        ApiResponse<Void> response = ApiResponse.of(
                HttpStatus.OK.value(),
                "Success",
                null
        );

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }

    @PostMapping("/auth/login")
    public ResponseEntity<ApiResponse<String>> authenticate(@RequestBody User user) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to authenticate...");
        }

        logger.info("POST HTTP request received at /api/auth/login");

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.OK.value(),
                "Success",
                jwtUtil.generateToken(userService.loadUserByUsernamePassword(user.getUsername(), user.getPassword()))
        );

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }

}

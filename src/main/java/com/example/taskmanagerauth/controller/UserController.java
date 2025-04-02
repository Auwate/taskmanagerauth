package com.example.taskmanagerauth.controller;

import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.service.UserService;
import com.example.taskmanagerauth.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @GetMapping("/auth/validate")
    public ResponseEntity<ApiResponse<Void>> validate() {

        if (logger.isDebugEnabled()) {
            logger.debug("Access token has been validated.");
        }

        logger.info("GET HTTP request received at /api/auth/validate");

        ApiResponse<Void> response = ApiResponse.of(
                HttpStatus.OK.value(),
                "Success",
                null
        );

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }

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
    public ResponseEntity<ApiResponse<Void>> authenticate(
            @RequestBody User user,
            HttpServletResponse httpServletResponse
    ) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to authenticate...");
        }

        logger.info("POST HTTP request received at /api/auth/login");

        httpServletResponse.addCookie(
            jwtService.generateJwtCookie(
                userService.loadUserByUsernamePassword(
                    user.getUsername(), user.getPassword()
                )
            )
        );

        ApiResponse<Void> response = ApiResponse.of(
                HttpStatus.OK.value(),
                "Success",
                null
        );

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }

}

package com.example.taskmanagerauth.controller;

import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.dto.LoginRequest;
import com.example.taskmanagerauth.dto.RegisterRequest;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.service.MfaService;
import com.example.taskmanagerauth.service.UserService;
import com.example.taskmanagerauth.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
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

    @Autowired
    private MfaService mfaService;

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
    public ResponseEntity<ApiResponse<Void>> register(
            @RequestBody RegisterRequest registerRequest
    ) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to register...");
        }

        logger.info("POST HTTP request received at /api/auth/register");

        User user = userService.createDatabaseUser(registerRequest.getUsername(), registerRequest.getPassword());

        userService.checkIfUserExists(user);
        mfaService.instantiateMfaForUser(user);
        userService.saveUser(user);

        ApiResponse<Void> response = ApiResponse.of(
                HttpStatus.OK.value(),
                "Success",
                null
        );

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }

    @PostMapping("/auth/login")
    public ResponseEntity<ApiResponse<Void>> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse httpServletResponse
    ) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to authenticate...");
        }

        logger.info("POST HTTP request received at /api/auth/login");

        // Load user
        User user = userService.getUserByUsernameAndPassword(loginRequest.getUsername(), loginRequest.getPassword());
        UserDetails userDetails = userService.createUserDetails(user);

        // Check if user has 2fa set up
        if (!mfaService.hasMfaEnabled(user)) {

            httpServletResponse.addCookie(
                    jwtService.generate2faCookie(
                            userDetails
                    )
            );

            ApiResponse<Void> response = ApiResponse.of(
                    362, // Custom code for requiring TOTP,
                    "Success",
                    null
            );

            return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT).body(response);

        }

        // Check TOTP
        mfaService.validatePassword(loginRequest.getTotp(), user);

        // Create access token cookie
        httpServletResponse.addCookie(
            jwtService.generateJwtCookie(
                userDetails
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

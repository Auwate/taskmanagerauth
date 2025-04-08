package com.example.taskmanagerauth.controller;

import com.example.taskmanagerauth.dto.impl.ApiResponse;
import com.example.taskmanagerauth.dto.impl.LoginRequest;
import com.example.taskmanagerauth.dto.impl.RegisterRequest;
import com.example.taskmanagerauth.dto.responses.LoginResult;
import com.example.taskmanagerauth.dto.responses.MfaRequired;
import com.example.taskmanagerauth.dto.responses.Success;
import com.example.taskmanagerauth.dto.responses.TotpRequired;
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

        // Process user
        LoginResult result = userService.login(loginRequest);

        return switch (result) {
            case Success success -> {
                httpServletResponse.addCookie(
                        jwtService.generateJwtCookie(
                                success.userDetails()
                        )
                );
                yield ResponseEntity.status(HttpStatus.OK).body(
                        ApiResponse.of(
                                HttpStatus.OK.value(),
                                "Success",
                                null
                        )
                );
            }
            case MfaRequired mfa -> {
                httpServletResponse.addCookie(
                        jwtService.generate2faCookie(
                                mfa.userDetails()
                        )
                );
                yield ResponseEntity.status(HttpStatus.OK).body(
                        ApiResponse.of(
                                362,
                                "Please enable mfa.",
                                null
                        )
                );
            }
            case TotpRequired totp -> {
                httpServletResponse.addCookie(
                        jwtService.generate2faCookie(
                                totp.userDetails()
                        )
                );
                yield ResponseEntity.status(HttpStatus.OK).body(
                        ApiResponse.of(
                                462,
                                "TOTP not provided.",
                                null
                        )
                );
            }

        };

    }

}

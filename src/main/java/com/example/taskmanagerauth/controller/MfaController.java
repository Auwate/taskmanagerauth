package com.example.taskmanagerauth.controller;

import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.service.MfaService;
import com.example.taskmanagerauth.service.UserService;
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
public class MfaController {

    @Autowired
    private MfaService mfaService;

    @Autowired
    private UserService userService;

    private static final Logger logger = LoggerFactory.getLogger(MfaController.class);

    @PostMapping("/auth/2fa/setup")
    public ResponseEntity<ApiResponse<Void>> setup(@RequestBody String totp) {

        if (logger.isDebugEnabled()) {
            logger.debug("2FA trying to be enabled.");
        }

        logger.info("POST HTTP request received at /api/auth/2fa/setup");

        mfaService.setupMfa(totp, userService.createUserDetails(userService.loadUserByContext()));

        ApiResponse<Void> response = ApiResponse.of(
                HttpStatus.OK.value(),
                "Success",
                null
        );

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }

    @GetMapping("/auth/2fa/generate")
    public ResponseEntity<ApiResponse<String>> generateUrl() {

        if (logger.isDebugEnabled()) {
            logger.debug("Trying to generate 2FA URL.");
        }

        logger.info("GET HTTP request received at /api/auth/2fa/generate");

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.OK.value(),
                "Success",
                mfaService.generateMfaCode()
        );

        return ResponseEntity.status(HttpStatus.OK).body(response);

    }

}

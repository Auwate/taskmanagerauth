package com.example.taskmanagerauth.exception.handler;

import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.exception.server.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionManager {

    @ExceptionHandler(UsernameTakenException.class)
    public ResponseEntity<ApiResponse<String>> handleUsernameTakenException(UsernameTakenException exception) {

        String message = "Bad Request: The username you provided is taken.";

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiResponse<String>> handleUsernameNotFoundException(UsernameNotFoundException exception) {

        String message = "Not Found: The username or password you provided were not linked to a user.";

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.NOT_FOUND.value(),
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);

    }



    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiResponse<String>> handleInvalidCredentialsException(InvalidCredentialsException exception) {

        String message = "Bad Request: Please provide valid credentials.";

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

    }

    @ExceptionHandler(JwtNotProvidedException.class)
    public ResponseEntity<ApiResponse<String>> handleJwtNotProvidedException(JwtNotProvidedException exception) {

        String message = "Bad Request: Please provide your access token for authentication.";

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

    }

    @ExceptionHandler(InvalidJwtException.class)
    public ResponseEntity<ApiResponse<String>> handleInvalidJwtException(InvalidJwtException exception) {

        String message = "Bad Request: Your access token is invalid.";

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiResponse<String>> handleExpiredJwtException(ExpiredJwtException exception) {

        String message = "Bad Request: Your access token is expired.";

        ApiResponse<String> response = ApiResponse.of(
                460, // Custom code for an expired access token
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

    }

}

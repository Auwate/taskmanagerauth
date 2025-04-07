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

    @ExceptionHandler(TotpNotProvidedException.class)
    public ResponseEntity<ApiResponse<String>> handleTotpNotProvidedException(TotpNotProvidedException exception) {

        String message = "Bad Request: One time password not provided.";

        ApiResponse<String> response = ApiResponse.of(
                461, // Custom code for requiring TOTP
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

    }

    @ExceptionHandler(MfaNotEnabledException.class)
    public ResponseEntity<ApiResponse<String>> handleMfaNotEnabledException(MfaNotEnabledException exception) {

        String message = "Bad Request: Please set up MFA for your account.";

        ApiResponse<String> response = ApiResponse.of(
                462, // Custom code for requiring TOTP
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

    }

    @ExceptionHandler(TotpInvalidException.class)
    public ResponseEntity<ApiResponse<String>> handleTotpInvalidException(TotpInvalidException exception) {

        String message = "Bad Request: One time password was incorrect.";

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.FORBIDDEN.value(),
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);

    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<String>> handleRuntimeException(RuntimeException exception) {

        String message = "Internal Server Error";

        ApiResponse<String> response = ApiResponse.of(
                HttpStatus.FORBIDDEN.value(),
                message,
                exception.getMessage()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);

    }

}

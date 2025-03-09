package com.example.taskmanagerauth.exception.handler;

import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.exception.server.ExpiredJwtException;
import com.example.taskmanagerauth.exception.server.InvalidCredentialsException;
import com.example.taskmanagerauth.exception.server.InvalidJwtException;
import com.example.taskmanagerauth.exception.server.JwtNotProvidedException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import java.io.IOException;

public class FilterExceptionManager {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger logger = LoggerFactory.getLogger(FilterExceptionManager.class);

    private void writeToResponse(HttpServletResponse response, ApiResponse<String> apiResponse) {

        response.setStatus(apiResponse.getStatus());
        response.setContentType("application/json");

        try {
            response.getWriter().write(mapper.writeValueAsString(apiResponse));
        } catch (JsonProcessingException jsonProcessingException) {
            logger.error("JsonProcessingException error: {}", jsonProcessingException.getMessage());
        } catch (IOException ioException) {
            logger.error("IOException error: {}", ioException.getMessage());
        }

    }

    public void handleInvalidCredentialsException(
            InvalidCredentialsException exception,
            HttpServletResponse response
    ) {

        String message = "Bad Request: Please provide valid credentials.";

        ApiResponse<String> apiResponse = ApiResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                message,
                exception.getMessage()
        );

        writeToResponse(response, apiResponse);

    }

    public void handleJwtNotProvidedException(
            JwtNotProvidedException exception,
            HttpServletResponse response
    ) {

        String message = "Bad Request: Please provide your access token for authentication.";

        ApiResponse<String> apiResponse = ApiResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                message,
                exception.getMessage()
        );

        writeToResponse(response, apiResponse);

    }

    public void handleInvalidJwtException(
            InvalidJwtException exception,
            HttpServletResponse response
    ) {

        String message = "Bad Request: Your access token is invalid.";

        ApiResponse<String> apiResponse = ApiResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                message,
                exception.getMessage()
        );

        writeToResponse(response, apiResponse);

    }

    public void handleExpiredJwtException(
            ExpiredJwtException exception,
            HttpServletResponse response
    ) {

        String message = "Bad Request: Your access token is expired.";

        ApiResponse<String> apiResponse = ApiResponse.of(
                460, // Custom code for an expired access token
                message,
                exception.getMessage()
        );

        writeToResponse(response, apiResponse);

    }

}

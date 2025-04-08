package com.example.taskmanagerauth.dto.impl;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ApiResponse<T> {

    private final int status;
    private final String message;
    private final T data;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private final String timestamp;

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public ApiResponse(int status, String message, T data, LocalDateTime timestamp) {
        this.status = status;
        this.message = message;
        this.data = data;
        this.timestamp = timestamp.format(FORMATTER);
    }

    // Factories

    public static <T> ApiResponse<T> of(int status, String message, T data) {
        return new ApiResponse<>(status, message, data, LocalDateTime.now());
    }

    public static <T> ApiResponse<T> of(int status, String message, T data, LocalDateTime timestamp) {
        return new ApiResponse<>(status, message, data, timestamp);
    }

    // Getters

    public int getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public T getData() {
        return data;
    }

    public String getTimestamp() {
        return timestamp;
    }

}

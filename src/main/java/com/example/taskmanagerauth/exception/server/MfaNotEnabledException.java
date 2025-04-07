package com.example.taskmanagerauth.exception.server;

public class MfaNotEnabledException extends RuntimeException {
    public MfaNotEnabledException(String message) {
        super(message);
    }
}

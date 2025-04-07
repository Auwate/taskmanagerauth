package com.example.taskmanagerauth.exception.server;

public class TotpInvalidException extends RuntimeException {
    public TotpInvalidException(String message) {
        super(message);
    }
}

package com.example.taskmanagerauth.exception.server;

public class TotpNotProvidedException extends RuntimeException{
    public TotpNotProvidedException(String message) {
        super(message);
    }
}

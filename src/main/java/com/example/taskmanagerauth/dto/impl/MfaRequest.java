package com.example.taskmanagerauth.dto.impl;

public class MfaRequest {

    private String totp;

    public MfaRequest(String totp) {
        this.totp = totp;
    }

    // Getters & setters

    public String getTotp() {
        return totp;
    }

    public void setTotp(String totp) {
        this.totp = totp;
    }

}

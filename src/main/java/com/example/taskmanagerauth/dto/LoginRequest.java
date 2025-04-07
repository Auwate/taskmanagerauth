package com.example.taskmanagerauth.dto;

public class LoginRequest {

    private String username;
    private String password;
    private String totp;

    public LoginRequest() {}

    public LoginRequest(String username, String password, String totp) {
        this.username = username;
        this.password = password;
        this.totp = totp;
    }

    // Getters & Setters

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getTotp() {
        return totp;
    }

    public void setTotp(String totp) {
        this.totp = totp;
    }

}

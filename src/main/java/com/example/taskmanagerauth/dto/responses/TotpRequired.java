package com.example.taskmanagerauth.dto.responses;

import org.springframework.security.core.userdetails.UserDetails;

public record TotpRequired(UserDetails userDetails) implements LoginResult {
}

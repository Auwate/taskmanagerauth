package com.example.taskmanagerauth.dto.responses;

import org.springframework.security.core.userdetails.UserDetails;

public record Success(UserDetails userDetails) implements LoginResult {
}

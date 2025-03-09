package com.example.taskmanagerauth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.taskmanagerauth.exception.server.InvalidJwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private static final long EXPIRATION_TIMER = 60 * 10; // 10 minutes

    public String generateToken(UserDetails userDetails) {
        Algorithm algorithm = Algorithm.HMAC512(secret);
        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withClaim("authorities", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIMER * 1000))
                .sign(algorithm);
    }

    public String extractUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getSubject();
        } catch (JWTDecodeException exception) {
            throw new InvalidJwtException("Invalid subject provided.");
        }
    }

    public List<String> extractAuthorities(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("authorities").asList(String.class);
        } catch (JWTDecodeException exception) {
            throw new InvalidJwtException("Invalid claims provided.");
        }
    }

    public boolean validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);

            JWTVerifier verifier = JWT.require(algorithm)
                    .build();

            verifier.verify(token);

            return true;
        } catch (TokenExpiredException exception) {
            throw new InvalidJwtException("Your access token is expired.");
        } catch (JWTVerificationException exception) {
            throw new InvalidJwtException("Your access token is invalid.");
        }
    }

}

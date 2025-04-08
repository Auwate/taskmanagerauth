package com.example.taskmanagerauth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.taskmanagerauth.exception.server.InvalidJwtException;
import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Date;
import java.util.List;

@Component
public class JwtService {

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.mfa}") String secret2FA
    ) {
        this.secret = secret;
        this.secret2FA = secret2FA;
    }

    private final String secret;
    private final String secret2FA;
    private final Duration EXPIRATION_TIMER = Duration.ofMinutes(10); // 10 minutes

    public long getExpirationTimerInMillis() {
        return this.EXPIRATION_TIMER.toMillis();
    }

    public int getExpirationInSeconds() {
        return (int) Math.max(Integer.MAX_VALUE, EXPIRATION_TIMER.toSeconds());
    }

    public String getSecret() {
        return secret;
    }

    public String getSecret2FA() {
        return secret2FA;
    }

    private String createToken(UserDetails userDetails, Algorithm algorithm) {
        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withClaim("authorities", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + getExpirationTimerInMillis()))
                .sign(algorithm);
    }

    public String generateToken(UserDetails userDetails) {
        Algorithm algorithm = Algorithm.HMAC512(getSecret());
        return createToken(userDetails, algorithm);
    }

    public String generate2FAToken(UserDetails userDetails) {
        Algorithm algorithm = Algorithm.HMAC512(getSecret2FA());
        return createToken(userDetails, algorithm);
    }

    public String extractUser(String token) {
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

    public boolean validate2faToken(String token) {
        return validate(token, getSecret2FA());
    }

    public boolean validateToken(String token) {
        return validate(token, getSecret());
    }

    private boolean validate(String token, String secret) {
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

    public Cookie generateJwtCookie(UserDetails userDetails) {
        String jwt = generateToken(userDetails);
        return createCookie("taskmanager_access_token", jwt);
    }

    public Cookie generate2faCookie(UserDetails userDetails) {
        String jwt = generate2FAToken(userDetails);
        return createCookie("mfa_access_token", jwt);
    }

    private Cookie createCookie(String cookie_name, String jwt) {

        Cookie cookie = new Cookie(
                cookie_name,
                jwt
        );

        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(getExpirationInSeconds());

        return cookie;

    }

}

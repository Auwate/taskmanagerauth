package com.example.taskmanagerauth.unit.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.taskmanagerauth.exception.server.InvalidJwtException;
import com.example.taskmanagerauth.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.util.Date;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class JwtServiceTests {

    @BeforeEach
    void setUp() {

        this.jwtService = new JwtService("Test");

        this.userDetails = new User(
                "Test id", // <- ID's are used instead of usernames
                "Test pass",
                Stream.of("USER").map(SimpleGrantedAuthority::new).toList()
        );

    }

    private JwtService jwtService;
    private UserDetails userDetails;

    /**
     * Test that JwtService correctly generates a valid JWT with at least 9 minutes of activity
     */
    @Test
    void testGenerate() {

        String testJWT = jwtService.generateToken(userDetails);

        DecodedJWT jwt = JWT.decode(testJWT);

        // Assertions
        assertTrue(jwt.getExpiresAt().getTime() - jwt.getIssuedAt().getTime() > Duration.ofMinutes(9).toMillis());
        assertEquals("Test id", jwt.getSubject());
        assertEquals("USER", jwt.getClaim("authorities").asList(String.class).getFirst());

    }

    /**
     * Test that JwtService correctly validates that a JWT is not expired
     */
    @Test
    void testValidate() {

        String testJWT = jwtService.generateToken(userDetails);

        // Assertions
        assertTrue(jwtService.validateToken(testJWT));

    }

    /**
     * Test that JwtService correctly throws an exception with an expired JWT
     */
    @Test
    void testValidateExpired() {

        Algorithm algorithm = Algorithm.HMAC256("Test");

        String testJwt = JWT.create()
                .withExpiresAt(new Date())
                .withIssuedAt(new Date())
                .sign(algorithm);

        assertThrows(InvalidJwtException.class, () -> jwtService.validateToken(testJwt));

    }

    /**
     * Test that JwtService will throw an exception with an invalid JWT
     */
    @Test
    void testValidateInvalid() {

        Algorithm algorithm = Algorithm.HMAC256("Invalid_secret");

        String testJwt = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + Duration.ofMinutes(10).toMillis()))
                .withIssuedAt(new Date())
                .sign(algorithm);

        assertThrows(InvalidJwtException.class, () -> jwtService.validateToken(testJwt));

    }

    /**
     * Test that JwtService can successfully extract the username
     */
    @Test
    void testExtractID() {

        String testJWT = jwtService.generateToken(userDetails);

        // Assertions
        assertEquals("Test id", jwtService.extractID(testJWT));

    }

    /**
     * Test that JwtService can successfully extract the authority
     */
    @Test
    void testExtractAuthority() {

        String testJWT = jwtService.generateToken(userDetails);

        // Assertions
        assertEquals("USER", jwtService.extractAuthorities(testJWT).getFirst());

    }

}

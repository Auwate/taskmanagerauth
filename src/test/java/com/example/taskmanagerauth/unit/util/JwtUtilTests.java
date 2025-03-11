package com.example.taskmanagerauth.unit.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.taskmanagerauth.exception.server.InvalidJwtException;
import com.example.taskmanagerauth.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.util.Date;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class JwtUtilTests {

    @BeforeEach
    void setUp() {

        this.jwtUtil = new JwtUtil("Test");

        this.userDetails = new User(
                "Test user",
                "Test pass",
                Stream.of("USER").map(SimpleGrantedAuthority::new).toList()
        );

    }

    private JwtUtil jwtUtil;
    private UserDetails userDetails;

    /**
     * Test that JwtUtil correctly generates a valid JWT with at least 9 minutes of activity
     */
    @Test
    void testGenerate() {

        String testJWT = jwtUtil.generateToken(userDetails);

        DecodedJWT jwt = JWT.decode(testJWT);

        // Assertions
        assertTrue(jwt.getExpiresAt().getTime() - jwt.getIssuedAt().getTime() > Duration.ofMinutes(9).toMillis());
        assertEquals("Test user", jwt.getSubject());
        assertEquals("USER", jwt.getClaim("authorities").asList(String.class).getFirst());

    }

    /**
     * Test that JwtUtil correctly validates that a JWT is not expired
     */
    @Test
    void testValidate() {

        String testJWT = jwtUtil.generateToken(userDetails);

        // Assertions
        assertTrue(jwtUtil.validateToken(testJWT));

    }

    /**
     * Test that JwtUtil correctly throws an exception with an expired JWT
     */
    @Test
    void testValidateExpired() {

        Algorithm algorithm = Algorithm.HMAC256("Test");

        String testJwt = JWT.create()
                .withExpiresAt(new Date())
                .withIssuedAt(new Date())
                .sign(algorithm);

        assertThrows(InvalidJwtException.class, () -> jwtUtil.validateToken(testJwt));

    }

    /**
     * Test that JwtUtil will throw an exception with an invalid JWT
     */
    @Test
    void testValidateInvalid() {

        Algorithm algorithm = Algorithm.HMAC256("Invalid_secret");

        String testJwt = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + Duration.ofMinutes(10).toMillis()))
                .withIssuedAt(new Date())
                .sign(algorithm);

        assertThrows(InvalidJwtException.class, () -> jwtUtil.validateToken(testJwt));

    }

    /**
     * Test that JwtUtil can successfully extract the username
     */
    @Test
    void testExtractUsername() {

        String testJWT = jwtUtil.generateToken(userDetails);

        // Assertions
        assertEquals("Test user", jwtUtil.extractUsername(testJWT));

    }

    /**
     * Test that JwtUtil can successfully extract the authority
     */
    @Test
    void testExtractAuthority() {

        String testJWT = jwtUtil.generateToken(userDetails);

        // Assertions
        assertEquals("USER", jwtUtil.extractAuthorities(testJWT).getFirst());

    }

}

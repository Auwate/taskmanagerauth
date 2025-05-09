package com.example.taskmanagerauth.unit.config;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.taskmanagerauth.config.JwtRequestFilter;
import com.example.taskmanagerauth.exception.handler.FilterExceptionManager;
import com.example.taskmanagerauth.exception.server.InvalidJwtException;
import com.example.taskmanagerauth.exception.server.JwtNotProvidedException;
import com.example.taskmanagerauth.service.UserService;
import com.example.taskmanagerauth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
public class JwtRequestFilterTests {

    private JwtRequestFilter jwtRequestFilter;

    @Mock
    private UserService userService;

    @Mock
    private FilterExceptionManager filterExceptionManager;

    @Mock
    private MockHttpServletRequest request;

    @Mock
    private MockHttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        JwtService jwtService = new JwtService("Test", "Test2");
        this.jwtRequestFilter = new JwtRequestFilter(userService, jwtService, filterExceptionManager);
    }

    /**
     * Tests the main test case of a successful authentication
     * @throws ServletException -> Immediate failure
     * @throws IOException -> Immediate failure
     */
    @Test
    void testFilterSuccess() throws ServletException, IOException {

        Algorithm algorithm = Algorithm.HMAC512("Test");

        String jwt = JWT.create()
                .withSubject("Test user")
                .withClaim("authorities", List.of("USER"))
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + Duration.ofMinutes(10).toMillis()))
                .sign(algorithm);

        Cookie access_token = new Cookie("taskmanager_access_token", jwt);

        when(request.getServletPath()).thenReturn("/auth/validate");

        when(request.getCookies()).thenReturn(new Cookie[]{access_token});
        when(userService.loadUserByJWT("Test user", List.of("USER"))).thenReturn(new User(
                "Test User",
                "JWT-AUTHENTICATED",
                Stream.of("USER").map(SimpleGrantedAuthority::new).toList()
        ));

        jwtRequestFilter.doFilter(request, response, filterChain);

        // Assertions
        verify(request, times(3)).getCookies();
        verify(filterChain, times(1)).doFilter(request, response);

    }

    /**
     * Test that doFilter will write a response detailing the exception
     * @throws ServletException -> Shouldn't occur
     * @throws IOException -> Shouldn't occur
     */
    @Test
    void testFilterThrowsWhenHeaderIsNull() throws ServletException, IOException {

        when(request.getCookies()).thenReturn(null);

        when(request.getServletPath()).thenReturn("/auth/validate");

        jwtRequestFilter.doFilter(request, response, filterChain);

        // Assertions
        verify(request, times(1)).getCookies();
        verify(filterExceptionManager, times(1)).handleJwtNotProvidedException(
                any(JwtNotProvidedException.class),
                eq(response)
        );

    }

    /**
     * Test that doFilter will throw an exception if Bearer is empty
     * @throws ServletException -> Shouldn't occur
     * @throws IOException -> Shouldn't occur
     */
    @Test
    void testFilterThrowsWhenHeaderIsEmpty() throws ServletException, IOException {

        when(request.getCookies()).thenReturn(new Cookie[]{});

        when(request.getServletPath()).thenReturn("/auth/validate");

        jwtRequestFilter.doFilter(request, response, filterChain);

        // Assertions
        verify(request, times(2)).getCookies();
        verify(filterExceptionManager, times(1)).handleJwtNotProvidedException(
                any(JwtNotProvidedException.class),
                eq(response)
        );

    }

    /**
     * Test that doFilter will throw an exception if the JWT is invalid
     * @throws ServletException -> Shouldn't occur
     * @throws IOException -> Shouldn't occur
     */
    @Test
    void testFilterThrowsWhenJWTIsInvalid() throws ServletException, IOException {

        Algorithm algorithm = Algorithm.HMAC512("Test");

        String jwt = JWT.create()
                .withSubject("Test user")
                .withClaim("authorities", List.of("USER"))
                .withIssuedAt(new Date())
                .withExpiresAt(new Date())
                .sign(algorithm);

        Cookie access_token = new Cookie("taskmanager_access_token", jwt);

        when(request.getCookies()).thenReturn(new Cookie[]{access_token});

        when(request.getServletPath()).thenReturn("/auth/validate");

        jwtRequestFilter.doFilter(request, response, filterChain);

        // Assertions
        verify(request, times(3)).getCookies();
        verify(filterExceptionManager, times(1)).handleInvalidJwtException(
                any(InvalidJwtException.class),
                eq(response)
        );

    }

}

package com.example.taskmanagerauth.config;


import com.example.taskmanagerauth.exception.handler.FilterExceptionManager;
import com.example.taskmanagerauth.exception.server.InvalidJwtException;
import com.example.taskmanagerauth.exception.server.JwtNotProvidedException;
import com.example.taskmanagerauth.service.UserService;
import com.example.taskmanagerauth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    public JwtRequestFilter(
            UserService userService,
            JwtService jwtService
    ) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.exceptionManager = new FilterExceptionManager();
    }

    private static final Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);

    public JwtRequestFilter(
            UserService userService,
            JwtService jwtService,
            FilterExceptionManager filterExceptionManager
    ) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.exceptionManager = filterExceptionManager;
    }

    private final UserService userService;
    private final JwtService jwtService;

    private final FilterExceptionManager exceptionManager;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        if (isPermitAllPath(request.getServletPath())) {
            doFilter(request, response, filterChain);
            return;
        }

        String cookie_name;

        if (isMfaPath(request.getServletPath())) {
            cookie_name = "mfa_access_token";
        } else {
            cookie_name = "taskmanager_access_token";
        }

        if (request.getCookies() == null || request.getCookies().length == 0) {
            exceptionManager.handleJwtNotProvidedException(
                    new JwtNotProvidedException("No tokens were provided."),
                    response
            );
            return;
        }

        String access_token;

        try {
            access_token = Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(cookie_name))
                    .toList().getFirst().getValue();
        } catch (Exception exception) {
            exceptionManager.handleJwtNotProvidedException(
                    new JwtNotProvidedException("Access token not provided."),
                    response
            );
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Access token: {}", access_token);
        }

        List<String> authorities = null;
        String username = null;

        try {

            if (jwtService.validateToken(access_token) || jwtService.validate2faToken(access_token)) {

                authorities = jwtService.extractAuthorities(access_token);
                username = jwtService.extractUser(access_token);

                if (logger.isDebugEnabled()) {
                    logger.debug("Username: {}, Authorities: {}", username, authorities);
                }

            }

        } catch (IndexOutOfBoundsException exception) {

            exceptionManager.handleJwtNotProvidedException(
                    new JwtNotProvidedException("Access token is not valid."),
                    response
            );

            return;

        } catch (InvalidJwtException exception) {

            exceptionManager.handleInvalidJwtException(
                    new InvalidJwtException("Access token is invalid or expired."),
                    response
            );

            return;

        }

        if (username != null && authorities != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userService.loadUserByJWT(username, authorities);

            // Create a token with the User details and their authorities
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
            );

            // Get metadata (remote IP, session details, etc.)
            usernamePasswordAuthenticationToken
                    .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set the SecurityContextHolder's authentication with the token
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

            if (logger.isDebugEnabled()) {
                logger.debug("Authentication: {}", (
                        (UserDetails) (
                                SecurityContextHolder
                                        .getContext()
                                        .getAuthentication()
                                        .getPrincipal()
                        )).getUsername()
                );
            }

        }

        filterChain.doFilter(request, response);

    }

    private boolean isPermitAllPath(String servletPath) {
        return SecurityConfig.permitAllPaths.contains(servletPath);
    }

    private boolean isMfaPath(String servletPath) {
        return SecurityConfig.mfaPath.contains(servletPath);
    }

}

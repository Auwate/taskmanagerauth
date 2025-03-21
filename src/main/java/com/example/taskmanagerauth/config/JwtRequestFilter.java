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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
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

        if (isPermitAlPath(request.getServletPath())) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authorizationHeader = request.getHeader("Authorization");

        List<String> authorities = null;
        String username = null;
        String jwt;

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {

            exceptionManager.handleJwtNotProvidedException(
                    new JwtNotProvidedException("Access token not provided."),
                    response
            );

            return;

        }

        try {

            jwt = authorizationHeader.substring(7);

            if (jwtService.validateToken(jwt)) {
                authorities = jwtService.extractAuthorities(jwt);
                username = jwtService.extractID(jwt);
            } else {
                throw new InvalidJwtException("Invalid access token.");
            }

        } catch (IndexOutOfBoundsException exception) {

            exceptionManager.handleJwtNotProvidedException(
                    new JwtNotProvidedException("Access token not provided."),
                    response
            );

            return;

        } catch (InvalidJwtException exception) {

            exceptionManager.handleInvalidJwtException(
                    new InvalidJwtException("Access token is not valid."),
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

        }

        filterChain.doFilter(request, response);

    }

    private boolean isPermitAlPath(String servletPath) {
        return SecurityConfig.permitAllPaths.contains(servletPath);
    }

}

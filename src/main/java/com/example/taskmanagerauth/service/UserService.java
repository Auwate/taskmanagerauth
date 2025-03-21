package com.example.taskmanagerauth.service;

import com.example.taskmanagerauth.entity.Role;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.exception.server.InvalidCredentialsException;
import com.example.taskmanagerauth.exception.server.UsernameTakenException;
import com.example.taskmanagerauth.repository.UserRepository;
import com.example.taskmanagerauth.service.JwtService;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncodingService passwordEncoder;
    private final JwtService jwtService;

    @Autowired
    public UserService(
            UserRepository userRepository,
            PasswordEncodingService passwordEncoder,
            JwtService jwtService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting loadUserByUsername with {}", username);
        }

        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("Invalid credentials provided.")
        );

        return new org.springframework.security.core.userdetails.User(
                String.valueOf(user.getId()), // Use the immutable ID instead of username
                user.getPassword(),
                mapRolesToAuthorities(user.getRoles())
        );

    }

    public UserDetails loadUserByJWT(String username, List<String> authorities) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting loadUserByJWT with {} and {}", username, authorities);
        }

        return new org.springframework.security.core.userdetails.User (
                username,
                "JWT-AUTHENTICATED",
                mapRolesToAuthorities(authorities.stream().map(Role::of).toList())
        );

    }

    public UserDetails loadUserByUsernamePassword(String username, String password) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting loadUserByUsernamePassword with {}", username);
        }

        UserDetails userDetails = loadUserByUsername(username);

        if (!passwordEncoder.getEncoder().matches(password, userDetails.getPassword())) {
            throw new InvalidCredentialsException("Invalid credentials provided.");
        }

        return userDetails;

    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();
    }

    @Transactional
    public void registerUser(User user) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to save user {}", user.getUsername());
        }

        if (userRepository.findByUsername(user.getUsername()).isEmpty()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepository.saveAndFlush(user);
        } else {
            throw new UsernameTakenException("Please provide a different username.");
        }

    }

}

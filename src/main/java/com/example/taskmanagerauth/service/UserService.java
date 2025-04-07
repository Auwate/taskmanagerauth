package com.example.taskmanagerauth.service;

import com.example.taskmanagerauth.entity.Role;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.exception.server.InvalidCredentialsException;
import com.example.taskmanagerauth.exception.server.UsernameTakenException;
import com.example.taskmanagerauth.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
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

    // UserDetail services

    public UserDetails createUserDetails(User user) {
        return new org.springframework.security.core.userdetails.User(
                String.valueOf(user.getId()),
                user.getPassword(),
                mapRolesToAuthorities(user.getRoles())
        );
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting loadUserByUsername with {}", username);
        }

        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("Invalid credentials provided.")
        );

        return createUserDetails(user);

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

    public User loadUserByContext() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails)authentication.getPrincipal();
        Long userId = Long.decode(userDetails.getUsername());

        return userRepository.findById(userId).orElseThrow(
                () -> new InvalidCredentialsException("User not found.")
        );

    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();
    }

    // Retrieve User objects

    public User getUserByUsernameAndPassword(String username, String password) {

        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("Invalid credentials provided.")
        );

        if (!passwordEncoder.getEncoder().matches(password, user.getPassword())) {
            throw new InvalidCredentialsException("Invalid credentials provided.");
        }

        return user;

    }

    public User getUserById(UserDetails userDetails) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to retrieve user with id {}", userDetails.getUsername());
        }

        return userRepository.findById(Long.parseLong(userDetails.getUsername())).orElseThrow(
                () -> new InvalidCredentialsException("User not found.")
        );

    }

    public void checkIfUserExists(User user) {
        userRepository.findByUsername(user.getUsername()).orElseThrow(
                () -> new UsernameTakenException("A user with this name already exists.")
        );
    }



    // Transactionals

    @Transactional
    public void saveUser(User user) {

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to save user {}", user.getUsername());
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.saveAndFlush(user);

    }

}

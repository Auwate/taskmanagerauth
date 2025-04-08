package com.example.taskmanagerauth.config;

import com.example.taskmanagerauth.service.PasswordEncodingService;
import com.example.taskmanagerauth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncodingService encodingService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    public static List<String> permitAllPaths = List.of(
            "/auth/register",
            "/auth/login"
    );

    public static List<String> mfaPath = List.of(
            "/auth/2fa/setup",
            "/auth/2fa/generate"
    );

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, CorsConfigurationSource configurationSource) throws Exception {
        http
                .cors((cors) -> cors.configurationSource(configurationSource))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, permitAllPaths.toArray(new String[0])).permitAll()
                        .anyRequest().authenticated()
                );
        http.authenticationProvider(daoAuthenticationProvider());
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(encodingService.getEncoder());
        provider.setUserDetailsService(userService);
        return provider;
    }

}

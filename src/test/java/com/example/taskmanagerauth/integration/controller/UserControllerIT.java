package com.example.taskmanagerauth.integration.controller;

import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.entity.Role;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.repository.UserRepository;
import com.example.taskmanagerauth.service.PasswordEncodingService;
import com.example.taskmanagerauth.util.JwtUtil;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Set;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ExtendWith(SpringExtension.class)
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UserControllerIT {

    @Autowired
    public UserControllerIT(
            TestRestTemplate testRestTemplate,
            UserRepository userRepository,
            PasswordEncodingService passwordEncodingService
    ) {
        this.testRestTemplate = testRestTemplate;
        this.userRepository = userRepository;
        this.passwordEncodingService = passwordEncodingService;
    }

    private final TestRestTemplate testRestTemplate;
    private final UserRepository userRepository;
    private final PasswordEncodingService passwordEncodingService;

    private JwtUtil jwtUtil;

    private static final String LOGIN_QUERY_URL = "/auth/login";
    private static final String REGISTER_QUERY_URL = "/auth/register";

    <T> HttpEntity<T> HttpEntityFactory(T data) {
        return new HttpEntity<>(data);
    }

    @BeforeEach
    void setUp() {
        this.jwtUtil = new JwtUtil("Test");
    }

    @Test
    @Order(1)
    void testRegisterSuccess() {

        User payload = new User();
        payload.setUsername("test_user");
        payload.setPassword("test_pass");
        payload.setRoles(Set.of(Role.of("USER")));

        ResponseEntity<ApiResponse<Void>> response = testRestTemplate.exchange(
                REGISTER_QUERY_URL,
                HttpMethod.POST,
                HttpEntityFactory(payload),
                new ParameterizedTypeReference<>() {}
        );

        // Assertions
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Success", response.getBody().getMessage());
        assertNull(response.getBody().getData());
        assertEquals(HttpStatus.OK.value(), response.getBody().getStatus());

        // Database
        User databaseUser = userRepository.findAll().getFirst();

        assertEquals(payload.getUsername(), databaseUser.getUsername());
        assertTrue(passwordEncodingService.getEncoder().matches(payload.getPassword(), databaseUser.getPassword()));
        assertEquals(1, payload.getRoles().size());
        assertEquals("USER", payload.getRoles().stream().findFirst().orElseThrow().getName());

    }

    @Test
    @Order(2)
    void testLoginSuccess() {

        User payload = new User(1L, "test_user", "test_pass");
        payload.setRoles(Set.of(Role.of("USER")));

        ResponseEntity<ApiResponse<String>> response = testRestTemplate.exchange(
                LOGIN_QUERY_URL,
                HttpMethod.POST,
                HttpEntityFactory(payload),
                new ParameterizedTypeReference<>() {}
        );

        // Assertions
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Success", response.getBody().getMessage());
        assertEquals(HttpStatus.OK.value(), response.getBody().getStatus());

        String testJWT = response.getBody().getData();
        jwtUtil.validateToken(testJWT);

        assertEquals("1", jwtUtil.extractID(testJWT));
        assertEquals("USER", jwtUtil.extractAuthorities(testJWT).getFirst());

    }

}

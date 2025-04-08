package com.example.taskmanagerauth.integration.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.taskmanagerauth.dto.ApiResponse;
import com.example.taskmanagerauth.dto.LoginRequest;
import com.example.taskmanagerauth.dto.RegisterRequest;
import com.example.taskmanagerauth.entity.Mfa;
import com.example.taskmanagerauth.entity.User;
import com.example.taskmanagerauth.repository.MfaRepository;
import com.example.taskmanagerauth.repository.UserRepository;
import com.example.taskmanagerauth.service.MfaService;
import com.example.taskmanagerauth.service.PasswordEncodingService;
import com.example.taskmanagerauth.service.JwtService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Date;
import java.util.List;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ExtendWith(SpringExtension.class)
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UserControllerIT {

    @Autowired
    public UserControllerIT(
            RestTemplate testRestTemplate,
            UserRepository userRepository,
            MfaRepository mfaRepository,
            PasswordEncodingService passwordEncodingService,
            JwtService jwtService,
            MfaService mfaService
    ) {
        this.testRestTemplate = testRestTemplate;
        this.userRepository = userRepository;
        this.mfaRepository = mfaRepository;
        this.passwordEncodingService = passwordEncodingService;
        this.jwtService = jwtService;
        this.mfaService = mfaService;
    }

    private final RestTemplate testRestTemplate;
    private final UserRepository userRepository;
    private final MfaRepository mfaRepository;
    private final PasswordEncodingService passwordEncodingService;
    private final JwtService jwtService;
    private final MfaService mfaService;

    private String secretKey;
    private String cookie;

    private static final String LOGIN_QUERY_URL = "https://localhost:9095/api/auth/login";
    private static final String REGISTER_QUERY_URL = "https://localhost:9095/api/auth/register";
    private static final String VALIDATE_QUERY_URL = "https://localhost:9095/api/auth/validate";
    private static final String GENERATE_QUERY_URL = "https://localhost:9095/api/auth/2fa/generate";
    private static final String SETUP_QUERY_URL = "https://localhost:9095/api/auth/2fa/setup";

    <T> HttpEntity<T> HttpEntityFactory(T data) {
        return new HttpEntity<>(data);
    }

    <T> HttpEntity<T> HttpEntityFactory(T data, HttpHeaders httpHeaders) {
        return new HttpEntity<>(data, httpHeaders);
    }

    private String generateToken(String username, List<String> authorities) {
        Algorithm algorithm = Algorithm.HMAC512("Test");
        return JWT.create()
                .withSubject(username)
                .withClaim("authorities", authorities)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 600 * 1000))
                .sign(algorithm);
    }

    HttpHeaders httpHeaderFactory() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.COOKIE, "taskmanager_access_token=" + generateToken("1", List.of("USER")));
        return headers;
    }

    HttpHeaders invalidHeaderFactory() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.COOKIE, "taskmanager_access_token=" + generateToken("2", List.of("USER")));
        return headers;
    }

    @Test
    @Order(1)
    void testRegisterSuccess() {

        RegisterRequest payload = new RegisterRequest("test_user", "test_pass");

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

        // User database assertions
        User databaseUser = userRepository.findAll().getFirst();

        assertEquals(payload.getUsername(), databaseUser.getUsername());
        assertTrue(passwordEncodingService.matches(payload.getPassword(), databaseUser.getPassword()));

        // Mfa database assertions
        Mfa databaseMfa = mfaRepository.findAll().getFirst();
        assertEquals(payload.getUsername(), databaseMfa.getUser().getUsername());
        assertEquals(false, databaseMfa.getMfaEnabled());

    }

    @Test
    @Order(2)
    void testLoginWithoutTotp() {

        LoginRequest payload = new LoginRequest("test_user", "test_pass", "");

        ResponseEntity<ApiResponse<String>> response = testRestTemplate.exchange(
                LOGIN_QUERY_URL,
                HttpMethod.POST,
                HttpEntityFactory(payload),
                new ParameterizedTypeReference<>() {}
        );

        // Assertions
        assertEquals(HttpStatus.TEMPORARY_REDIRECT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Success", response.getBody().getMessage());
        assertEquals(362, response.getBody().getStatus());

        // Get cookie
        String testJWT = response.getHeaders().getFirst("Set-Cookie");
        assertNotNull(testJWT);

        testJWT = testJWT.substring(testJWT.indexOf("=") + 1, testJWT.indexOf(";"));

        jwtService.validate2faToken(testJWT);

        assertEquals("1", jwtService.extractUser(testJWT));
        assertEquals("USER", jwtService.extractAuthorities(testJWT).getFirst());

        // For use in next test
        this.cookie = testJWT;

    }

    @Test
    @Order(3)
    void generateTotp() {

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.COOKIE, "mfa_access_token=" + this.cookie);

        ResponseEntity<ApiResponse<String>> response = testRestTemplate.exchange(
                GENERATE_QUERY_URL,
                HttpMethod.GET,
                HttpEntityFactory(null, headers),
                new ParameterizedTypeReference<>() {}
        );

        // Assertions
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Success", response.getBody().getMessage());
        assertEquals(HttpStatus.OK.value(), response.getBody().getStatus());

        this.secretKey = mfaService.decrypt(mfaRepository.findAll().getFirst().getMfaSecretKey());

        assertEquals(
                "otpauth://totp/TaskManagerAuth:1?secret=" + secretKey + "&issuer=TaskManagerAuth\n",
                response.getBody().getData()
        );

    }

    @Test
    @Order(4)
    void setupTotp() {

        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        String payload = String.valueOf(authenticator.getTotpPassword(secretKey));

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.COOKIE, "mfa_access_token=" + this.cookie);


        ResponseEntity<ApiResponse<String>> response = testRestTemplate.exchange(
                SETUP_QUERY_URL,
                HttpMethod.POST,
                HttpEntityFactory(payload, headers),
                new ParameterizedTypeReference<>() {}
        );

        // Assertions
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Success", response.getBody().getMessage());
        assertEquals(HttpStatus.OK.value(), response.getBody().getStatus());

        // Database
        User userDB = userRepository.findAll().getFirst();
        assertTrue(userDB.getMfa().getMfaEnabled());

    }

    @Test
    @Order(5)
    void testLoginSuccess() {

        GoogleAuthenticator authenticator = new GoogleAuthenticator();
        String totp = String.valueOf(authenticator.getTotpPassword(secretKey));
        LoginRequest payload = new LoginRequest("test_user", "test_pass", totp);

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

        String testJWT = response.getHeaders().getFirst("Set-Cookie");
        assertNotNull(testJWT);

        testJWT = testJWT.substring(testJWT.indexOf("=") + 1, testJWT.indexOf(";"));

        jwtService.validateToken(testJWT);

        assertEquals("1", jwtService.extractUser(testJWT));
        assertEquals("USER", jwtService.extractAuthorities(testJWT).getFirst());

    }

    @Test
    @Order(6)
    void testValidateSuccess() {

        ResponseEntity<ApiResponse<String>> response = testRestTemplate.exchange(
                VALIDATE_QUERY_URL,
                HttpMethod.GET,
                HttpEntityFactory(null, httpHeaderFactory()),
                new ParameterizedTypeReference<>() {}
        );

        // Assertions
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Success", response.getBody().getMessage());
        assertEquals(HttpStatus.OK.value(), response.getBody().getStatus());

    }

}

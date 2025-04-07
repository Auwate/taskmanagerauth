package com.example.taskmanagerauth.unit.entity;

import com.example.taskmanagerauth.entity.Mfa;
import com.example.taskmanagerauth.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@ActiveProfiles("test")
public class MfaTests {

    /**
     * Test the basic behavior of the Mfa entity class
     */
    @Test
    void testBasicBehavior() {

        // Creation
        Mfa testMfa = new Mfa();

        // Setters
        testMfa.setMfaEnabled(true);
        testMfa.setUser(new User(1L, "Test", "Test"));
        testMfa.setId(1L);
        testMfa.setMfaSecretKey("Test");

        // Getters
        assertEquals(true, testMfa.getMfaEnabled());
        assertEquals(1L, testMfa.getUser().getId());
        assertEquals("Test", testMfa.getMfaSecretKey());
        assertEquals("Test", testMfa.getUser().getUsername());
        assertEquals("Test", testMfa.getUser().getPassword());

    }

}

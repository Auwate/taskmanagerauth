package com.example.taskmanagerauth.unit.entity;

import com.example.taskmanagerauth.entity.Role;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@ActiveProfiles("test")
public class RoleTests {

    /**
     * Basic test
     * ---
     * Test that the normal behavior of creation/getter/setter works
     */
    @Test
    void testBasicBehavior() {

        // Create
        Role testRole = new Role();

        // Setters
        testRole.setId(1L);
        testRole.setName("Test name");

        // Getters
        assertEquals(1L, testRole.getId());
        assertEquals("Test name", testRole.getName());

    }

    /**
     * Test that the factory creates a new Role
     */
    @Test
    void testFactory() {

        Role factoryRole = Role.of("Test name");

        // Assert
        assertEquals("Test name", factoryRole.getName());

    }

}

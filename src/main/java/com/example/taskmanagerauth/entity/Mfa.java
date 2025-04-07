package com.example.taskmanagerauth.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;

@Entity
@Table(name = "mfa")
public class Mfa {

    @Id
    @SequenceGenerator(name = "mfa_seq", sequenceName = "mfa_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "mfa_seq")
    private Long id;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    @JsonBackReference
    private User user;

    @Column(name = "mfaEnabled", nullable = false)
    private Boolean mfaEnabled;

    @Column(name = "mfaSecretKey", nullable = false)
    private String mfaSecretKey;

    public Mfa() {}

    public Mfa(Long id, User user, Boolean mfaEnabled, String mfaSecretKey) {
        this.id = id;
        this.user = user;
        this.mfaEnabled = mfaEnabled;
        this.mfaSecretKey = mfaSecretKey;
    }

    // Factory

    public static Mfa of(User user, Boolean mfaEnabled, String mfaSecretKey) {
        return new Mfa(null, user, mfaEnabled, mfaSecretKey);
    }

    // Getters & Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Boolean getMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(Boolean mfa_enabled) {
        this.mfaEnabled = mfa_enabled;
    }

    public String getMfaSecretKey() {
        return mfaSecretKey;
    }

    public void setMfaSecretKey(String mfa_secret_key) {
        this.mfaSecretKey = mfa_secret_key;
    }

}

package com.example.taskmanagerauth.repository;

import com.example.taskmanagerauth.entity.Mfa;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MfaRepository extends JpaRepository<Mfa, Long> {}

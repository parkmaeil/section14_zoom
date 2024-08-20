package com.example.security.repository;

import com.example.security.entity.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository  extends JpaRepository<Customer, Long> {
    public Optional<Customer> findByUsername(String username);
}

package com.example.security.service;

import com.example.security.entity.Role;
import com.example.security.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleService {

    @Autowired
    private RoleRepository roleRepository;

    public Role findByName(String name){
           return roleRepository.findByName(name);
    }
}

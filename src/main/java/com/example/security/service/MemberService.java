package com.example.security.service;

import com.example.security.entity.Customer;
import com.example.security.entity.Role;
import com.example.security.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class MemberService {

    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private RoleService roleService;
    // 회원가입 동작
    public Customer memberRegister(Customer customer){
        // 1. 패스워드 암호화
        String encodePassword=passwordEncoder.encode(customer.getPassword());
        customer.setPassword(encodePassword);
        // 2. 권한부여(USER, MANAGER, ADMIN) : member_roles : USER(1)
        Set<Role> roles=new HashSet<>();
        Role userRole=roleService.findByName("USER");
        roles.add(userRole);
        customer.setRoles(roles);
        return memberRepository.save(customer); // insert SQL~
    }
}

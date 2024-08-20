package com.example.security.entity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class CustomerUserDetails  extends User {  // User(username, password ,authorities)
    private Customer customer; // 로그인에 성공한 고객 정보(이름, 나이, 이메일, 주소....)
    public CustomerUserDetails(Customer customer) {                                            // USER, MANAGER, ADMIN
        super(customer.getUsername(), customer.getPassword(), getAuthorities(customer.getRoles()));// SQL~
        this.customer=customer; // 추가
    }
   // String username, String password, Collection<? extends GrantedAuthority> authorities
    public  static Collection<? extends GrantedAuthority> getAuthorities(Set<Role> roles){// USER, MANAGER, ADMIN
        return roles.stream()
                .map(role->new SimpleGrantedAuthority("ROLE_"+role.getName())) // ROLE_USER, ROLE_MANAGER, ROLE_ADMIN
                .collect(Collectors.toList());
    }
    public void setCustomer(Customer customer){
         this.customer=customer;
    }
    public Customer getCustomer(){
        return customer;
    }
}

package com.example.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Generated;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Customer { // 고객(Object) -> ORM -> TABLE : Review(리뷰)
    @Id // PK
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;  // 일련번호

    @Column(nullable = false, unique = true)
    private String username; // 고객ID
    private String password; //  고객의 비밀번호(암호화)
    private String customerName; // 고객이름 -> customer_name ? , customerName
    private  int age; // 나이
    private String rating; // 등급
    private String occupation; // 직업
    private String email; // 이메일

    @Column(columnDefinition = "int default  0")
    private int reserves; // 적립금

    // JPA에게 나는 연관관계의 주인이 아니다.(FK X)
    // 1 (Customer) : N(Review)
    // CascadeType.ALL : 고객에 삭제가 되면 연결된 리부 정보도 함께 삭제 되어야 한다.
    // fetch = FetchType.EAGER : 즉시로딩 - 메모리를 비효율적 사용
    // fetch = FetchType.LAZY : 지연로딩 - 메모리 절약, 참조순환(N+1 : 데이터베이스참조가 계속 발생)
    @OneToMany(mappedBy = "customer", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Review> reviews; // 오브젝트는 컬럼으로 만들어지지 않는다.

    @OneToMany(mappedBy ="customer", cascade = CascadeType.ALL )
    private List<Cart> carts;

    // 한명의 회원은 여러개의 권한(중복 - Set)을 가지고 있다.
    @ManyToMany(fetch = FetchType.LAZY)  // 지연로딩
    @JoinTable(
        name="member_roles",
        joinColumns = @JoinColumn(name="customer_id"),
        inverseJoinColumns = @JoinColumn(name="role_id")
    )
    private Set<Role> roles; // 고객의 권한정보도 함께 가져올건지 아니면 가지고 오지 않을건지
}
/*
  create table Customer (
        age integer not null,
        reserves int default  0,
        id bigint not null auto_increment,
        customerName varchar(255),
        occupation varchar(255),
        password varchar(255),
        rating varchar(255),
        username varchar(255) not null,
        primary key (id)
    ) engine=InnoDB

    create table member_roles (
        customer_id bigint not null,
        role_id bigint not null,
        primary key (customer_id, role_id)
    ) engine=InnoDB

    alter table member_roles
       add constraint FK24m8v3bgf3s50qmbkt47hvegn
       foreign key (role_id)
       references Role (id)

       alter table member_roles
       add constraint FKb8gv6gk3gn2iecaf7kgrs637i
       foreign key (customer_id)
       references Customer (id)

 */
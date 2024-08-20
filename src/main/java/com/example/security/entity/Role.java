package com.example.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Role { // 1. USER, 2. MANAGER  3.  ADMIN

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private  Long id; // 1 , 2,  3,

    @Column(unique = true)
    private String name; // USER, MANAGER, ADMIN
}
/*
  create table Role (
        id bigint not null auto_increment,
        name varchar(255),
        primary key (id)
    ) engine=InnoDB

 alter table Role
       add constraint UK_7d8a768x6aiuvmsa24hqiharg unique (name)

 */
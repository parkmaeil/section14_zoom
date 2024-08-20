package com.example.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Cart {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    // 고객정보(FK)
    @ManyToOne
    @JoinColumn(name = "customer_id" , nullable = false)
     private Customer customer;

     // 책의정보(FK)
     @ManyToOne
     @JoinColumn(name = "book_id" , nullable = false)
    private Book book;

    private int quantity; //  수량
    private Date cartDate; // 구매일자
}
/*
 create table Cart (
        quantity integer not null,
        book_id bigint not null,
        cartDate datetime(6),
        customer_id bigint not null,
        id bigint not null auto_increment,
        primary key (id)
    ) engine=InnoDB

       alter table Cart
       add constraint FKm5ku5ea0qccwca07ju2idkl8e
       foreign key (book_id)
       references Book (id)

       alter table Cart
       add constraint FKjh6lsweiw8ipasfagjwmmgi9u
       foreign key (customer_id)
       references Customer (id)

 */
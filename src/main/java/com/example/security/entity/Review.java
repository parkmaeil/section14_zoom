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
public class Review {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 이 리뷰를 누가(Customer) 작성했는가?
   //   N(Review) :   1(Customer)
    @ManyToOne
    @JoinColumn(name="customer_id", nullable = false) // FK
    private Customer customer; // 오브젝트는 컬럼으로 만들어지지 않는다.(FK)

    // 어떤 책에 리뉴가 작성이 되었는가?
    //  N(Review) :   1(Book)
    @ManyToOne
    @JoinColumn(name = "book_id", nullable = false)
    private Book book; // 오브젝트는 컬럼으로 만들어지지 않는다.(FK)

    private int cost; // 평점
    private String content; //  내용
    private Date createdAt;
}
/*
    create table Review (
        cost integer not null,
        book_id bigint not null, -- FK
        createdAt datetime(6),
        customer_id bigint not null, -- FK
        id bigint not null auto_increment,
        content varchar(255),
        primary key (id)
    ) engine=InnoDB

       alter table Review
       add constraint FKl3n8g20ecmr15g83y0g3evv2q
       foreign key (customer_id)
       references Customer (id)

        alter table Review
       add constraint FK8d76td2o7d2d8foei85l93b9w
       foreign key (book_id)
       references Book (id)
 */


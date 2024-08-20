package com.example.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class BookImage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 어떤 책에 속한 이미지인가?
    @ManyToOne
    @JoinColumn(name="book_id", nullable = false)
    private Book book; // 오브책트는  컬럼을 만들수없다(FK)
    private int type;  // 1, 2, 3
    private String path; // 파일경로(이름)

}
/*
create table BookImage (
        type integer not null,
        book_id bigint not null,
        id bigint not null auto_increment,
        path varchar(255),
        primary key (id)
    ) engine=InnoDB

     alter table BookImage
       add constraint FKj7yq0ebj03hom9mm9qom3p0kl
       foreign key (book_id)
       references Book (id)

 */
package com.example.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Book {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // 일련번호
    private String title; // 제목
    private int price; // 가격
    private String author; // 저자
    private int page;  // 페이지

    // 책정보를 가져올께 리뷰정보(여러개)까지 함께 가져오기
    @OneToMany(mappedBy ="book", cascade = CascadeType.ALL)
    private List<Review> reviews;

    // 이첵에대한 이미지 정보를 함께 가져와야한다.
    @OneToMany(mappedBy ="book", cascade = CascadeType.ALL)
    private List<BookImage> bookImages;

    @OneToMany(mappedBy ="book", cascade = CascadeType.ALL)
    private List<Cart> carts;

}

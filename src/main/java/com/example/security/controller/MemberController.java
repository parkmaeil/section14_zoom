package com.example.security.controller;

import com.example.security.entity.Customer;
import com.example.security.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/member")
public class MemberController {

    @Autowired
    private MemberService memberService;

    @GetMapping("/memberRegister")
    public String memberRegisterGet(){
         return "member/register"; // register.html(회원가입)
    }

    @PostMapping("/memberRegister")
    public String memberRegisterPost(Customer customer){
        memberService.memberRegister(customer);
        return "redirect:/"; // 시작페이지(index.html)
    }
}

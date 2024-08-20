package com.example.security.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class TestController {

    @Secured("ROLE_MANAGER")
    @GetMapping("/info")
    public @ResponseBody String info(){
          return "개인정보";
    }

    //@Secured("ROLE_ADMIN")
    @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "관리자정보";
    }
}

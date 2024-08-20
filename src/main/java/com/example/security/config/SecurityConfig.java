package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

       @Bean
       public BCryptPasswordEncoder passwordEncoder(){
            // 회원가입시 패스워드를 암호화 할때 사용
           return new BCryptPasswordEncoder();
       }
        // SecurityFilterChain
        @Bean                                                                                   //  클라이언트의 요청 URL
         public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
                   // 권한부여 규칙 정한다.
                   http.authorizeHttpRequests(authz->authz
                         //  .requestMatchers("/ui/**").permitAll() // /ui/** 인증없이 접근 허용
                         //  .requestMatchers("/admin/**").hasRole("ADMIN") // 인증이 되어야 되고, ADMIN권한인 사람만 요청을 허용
                         //  .requestMatchers("/user/**").hasAnyRole("USER","ADMIN")
                         //  .anyRequest().authenticated() // 나머지 모든 요청은 인증을 요구
                           .requestMatchers("/api/**").authenticated() // /api/** 경로는 인증 후 접근이 가능
                           .requestMatchers("/books/**").authenticated() // /books/** 경로는 인증 후 접근이 가능
                           .anyRequest().permitAll() // 나머지 모든 경로는 인증 없이 접근 허용
                   )
                   .formLogin(form -> form
                           .loginPage("/") // login page URL -> / -> MainController -> View(inedx.html)
                           // UsernamePasswordAuthenticationFilter ----> UserDetailsService(interface)
                           .loginProcessingUrl("/loginProcess") // 스프링시큐리티(URL 가로채기:username, password)에게 제어권을 넘긴다.
                           .defaultSuccessUrl("/")
                           .failureUrl("/?error=true")
                           .permitAll()
                   )
                   .logout(logout->logout
                           .logoutUrl("/logout") // 로그아웃 URL -> 스프링시큐리티가 가로채기를 해서 로그아웃 처리를 해준다.
                           .logoutSuccessUrl("/?logout=true")
                           .invalidateHttpSession(true)
                           .deleteCookies("JSESSIONID")
                   );
            return http.build();
        }
}

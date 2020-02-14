package com.example.project.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
// @EnableWebSecurity Spring Boot 에서 자동 등록을 해주므로 생략 가능
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // get "/", get "/info" 으로 오는 요청은 인증을 하지않고 접근하는 설정
        http
                .authorizeRequests()
                .mvcMatchers(
                        "/",
                        "/info",
                        "/account/**"
                )
                .permitAll();
        // get "/admin" 으로 오는 요청은 ADMIN 권한을 가지고있는 사용자만 접근하는 설정
        http
                .authorizeRequests()
                .mvcMatchers("/admin")
                .hasRole("ADMIN");

        // 그외 모든 페이지는 단순 인증을 하면 접근하는 설정
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated();

        // form 로그인 기능을 사용하겠다.
        http
                .formLogin()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // password {암호화 방식} 을 추가하면 비밀번호를 해당 암호화로 변경됩니다.
        // {noop} Spring Security 기본 장착된 인코더
        auth
                .inMemoryAuthentication()
                .withUser("jjunpro-1")
                .password("{noop}123")
                .roles("USER");

        auth
                .inMemoryAuthentication()
                .withUser("jjunpro-2")
                .password("{noop}123")
                .roles("ADMIN");
    }
}

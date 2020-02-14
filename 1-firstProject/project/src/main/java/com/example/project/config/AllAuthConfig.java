package com.example.project.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 모든 요청이 인증 없이 접근을 허용하는 Config
 * */
//@Configuration
@Order(Ordered.LOWEST_PRECEDENCE - 100) // 실행 우선순위를 최상위로 올립니다.
public class AllAuthConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .mvcMatchers(
                        "/",
                        "/info",
                        "/account/**"
                )
                .permitAll();

        http
                .authorizeRequests()
                .mvcMatchers("/admin")
                .hasRole("ADMIN");

        http.formLogin();
        http.httpBasic();
    }
}

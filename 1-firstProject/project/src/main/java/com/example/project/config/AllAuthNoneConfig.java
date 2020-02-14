package com.example.project.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * account 요청만 인증 없이 접근을 허용하는 Config
 */
//@Configuration
@Order(Ordered.LOWEST_PRECEDENCE - 10) // 실행 우선순위를 하위로 내립니다.
public class AllAuthNoneConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/account/**")
                .authorizeRequests()
                .anyRequest()
                .permitAll();
    }
}

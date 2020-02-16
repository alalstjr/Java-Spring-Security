package com.example.project.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.security.Security;
import java.util.Arrays;
import java.util.List;

@Configuration
// @EnableWebSecurity Spring Boot 에서 자동 등록을 해주므로 생략 가능
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // AccessDecisionManager
    public AccessDecisionManager accessDecisionManager() {
        /**
         * AccessDecisionManager -> AccessDecisionVoter -> webExpressionVoter -> setExpressionHandler -> DefaultWebSecurityExpressionHandler -> roleHierarchy
         * */
        // roleHierarchy
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER ");

        // DefaultWebSecurityExpressionHandler
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        // setExpressionHandler
        // WebExpressionVoter 를 사용하겠습니다.
        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        webExpressionVoter.setExpressionHandler(handler);

        // AccessDecisionVoter
        // Voter 목록을 만듭니다.
        List<AccessDecisionVoter<? extends Object>> voters = Arrays.asList(webExpressionVoter);

        return new AffirmativeBased(voters);
    }

    public SecurityExpressionHandler securityExpressionHandler() {
        // roleHierarchy
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER ");

        // DefaultWebSecurityExpressionHandler
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        return handler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // get "/", get "/info" 으로 오는 요청은 인증을 하지않고 접근하는 설정
        http
                .authorizeRequests()
                .mvcMatchers(
                        "/",
                        "/info",
                        "/account/**",
                        "/signup/**"
                )
                .permitAll();
        // get "/admin" 으로 오는 요청은 ADMIN 권한을 가지고있는 사용자만 접근하는 설정
        http
                .authorizeRequests()
                .mvcMatchers("/admin")
                .hasRole("ADMIN")
                .mvcMatchers("user")
                .hasRole("USER");

        // 그외 모든 페이지는 단순 인증을 하면 접근하는 설정
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .expressionHandler(securityExpressionHandler());
        //.accessDecisionManager(accessDecisionManager());

        // form 로그인 기능을 사용하겠다.
        http
                .formLogin()
                .and()
                .httpBasic();

        // 특정 페이지 검증 필터 제외 하지만 WebSecurity 사용 권장
        //        http
        //                .authorizeRequests()
        //                .requestMatchers(PathRequest
        //                        .toStaticResources()
        //                        .atCommonLocations());

        /**
         * 기본적으로 사하는 SecurityContextHolder는 getContextHolderStrategy 설정 가능합니다.
         * SecurityContext 정보를 어떻게 유지할 것인가 어디까지 공유할 것인가 를 설정가능합니다.
         * 기본은 ThreadLocal 입니다.
         *
         * SecurityContextHolder.MODE_INHERITABLETHREADLOCAL 를 사용하면 현재
         * Thread 에서 하위 Thread 생성하는 Thread 에도 SecurityContextHolder가 공유가 됩니다.
         *
         * */
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    // 인메모리 유저 생성 방법
    //    @Override
    //    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //        // password {암호화 방식} 을 추가하면 비밀번호를 해당 암호화로 변경됩니다.
    //        // {noop} Spring Security 기본 장착된 인코더
    //        auth
    //                .inMemoryAuthentication()
    //                .withUser("jjunpro-1")
    //                .password("{noop}123")
    //                .roles("USER");
    //
    //        auth
    //                .inMemoryAuthentication()
    //                .withUser("jjunpro-2")
    //                .password("{noop}123")
    //                .roles("ADMIN");
    //    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        // 기본 제외 방법
        web
                .ignoring()
                .mvcMatchers("/favicon.ico");

        // Spring 프레임워크 제외방법
        web
                .ignoring()
                .requestMatchers(PathRequest
                        .toStaticResources()
                        .atCommonLocations());
    }
}

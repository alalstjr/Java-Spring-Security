--------------------
# Java Spring Security
--------------------

# 목차

- [1. Spring Security 적용](#Spring-Security-적용)
    - [1. 스프링 시큐리티 설정하기](#스프링-시큐리티-설정하기)
    - [2. properties 활용하여 인메모리 유저 추가](#properties-활용하여-인메모리-유저-추가)
    - [3. configure 활용하여 인메모리 유저 추가](#configure-활용하여-인메모리-유저-추가)
    
# Spring Security 적용

의존성 추가

~~~
dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-security'
}
~~~

## 스프링 시큐리티 설정하기

~~~
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // get "/", get "/info" 으로 오는 요청은 인증을 하지않고 접근하는 설정
        http
                .authorizeRequests()
                .mvcMatchers(
                        "/",
                        "/info"
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
}
~~~

## properties 활용하여 인메모리 유저 추가

처음 시큐리티가 만들어주는 user 의 인메모리 유저정보는 UserDetailsServiceAutoConfiguration.class 위치에서 만들어 집니다.

~~~
2019-07-24 11:13:41.245  INFO 10848 --- [           main] .s.s.UserDetailsServiceAutoConfiguration : 
Using generated security password: 114284e0-656a-4fdf-b623-9b552a85b6c8
~~~

해당 인메모리 유저정보는 application.properties 에서 설정이 가능합니다.

~~~
spring.security.user.name=admin
spring.security.user.password=admin
spring.security.user.roles=ADMIN
~~~

## configure 활용하여 인메모리 유저 추가

configure(AuthenticationManagerBuilder auth) Override 메소드를 사용합니다.

~~~
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
~~~

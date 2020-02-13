--------------------
# Java Spring Security
--------------------

# 목차

- [1. Spring Security 적용](#Spring-Security-적용)
    - [1. 스프링 시큐리티 설정하기](#스프링-시큐리티-설정하기)
    - [2. properties 활용하여 인메모리 유저 추가](#properties-활용하여-인메모리-유저-추가)
    - [3. configure 활용하여 인메모리 유저 추가](#configure-활용하여-인메모리-유저-추가)
- [2. JPA 를 활용한 spring security](#JPA-를-활용한-spring-security)
- [3. PasswordEncoder](#PasswordEncoder)
    
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

# JPA 를 활용한 spring security

UserDetailsService.interface DAO(Data Access Object) 를 통해서 DB DATA의 유저 정보를 읽어옵니다.
`DB 저장소에 들어있는 유저정보를 가지고 인증을 할때 사용`하는 인터페이스 입니다.

~~~
@Entity
public class Account {

    @Id
    @GeneratedValue
    private Long id;

    @Column(unique = true)
    private String username;

    private String password;
    private String role;

    // Getter, Setter

    // 암호를 인코더하는 메소드
    public void encodePassword() {
        this.password = "{noop}" + this.password;
    }
}

public interface AccountRepository extends JpaRepository<Account, Long> {
    Account findByUsername(String username);
}

@Service
public class AccountService implements UserDetailsService {

    private final AccountRepository accountRepository;

    public AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username);

        /**
         * Username 값이 DATA DB 에 존재하지 않는 경우
         * UsernameNotFoundException 에러 메소드를 사용합니다.
         * */
        if (account == null) {
            throw new UsernameNotFoundException(username);
        }

        /**
         * Username 값이 DATA DB 에 존재하는 경우
         * Account 타입을 -> UserDetails 타입으로 변경하여 반환해야합니다.
         * 이때 타입을 변환하도록 도와주는 User.class 를 사용합니다.
         *
         * @see User
         * */

        return User
                .builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    /**
     * 사용자로부터 받은 password 값을 encode 암호화 해서 저장합니다.
     */
    public Account save(Account account) {
        account.encodePassword();
        return accountRepository.save(account);
    }
}

@RestController
public class AccountController {

    private final AccountRepository accountRepository;

    public AccountController(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @GetMapping("/account/{username}/{password}/{role}")
    public Account createAccount(
            @ModelAttribute
                    Account account
    ) {
        return accountRepository.save(account);
    }
}

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .mvcMatchers(
                        "/",
                        "/info",
>                        "/account/**"
                )
                .permitAll();

        // "/account/**" 추가 함므로써 해당 경로의 모든곳은 인증요청을 하지 않습니다.
    }
}
~~~

Spring Security 에서 명시적으로 선언을 하려면 SecurityConfig.class 에서
AccountService 의존성 주입을 받고 configure(AuthenticationManagerBuilder auth) 메소드에서 
AccountService.class 가 UserDetailsService 구현체를 사용해서 유저 정보를 DB 에서 가져와서 사용하라고 
auth.getDefaultUserDetailsService(accountService) 선언해줍니다.

하지만 UserDetailsService Bean으로 등록만 되어있으면 해당 class를 자동으로 참조하여 사용합니다.

# PasswordEncoder

- 비밀번호는 반드시 인코딩해서 저장해야 합니다. 단방향 암호화 알고리듬으로.
    - 스프링 시큐리티가 제공하는 PasswordEndoer는 특정한 포맷으로 동작함.
    - {id}encodedPassword
    - 다양한 해싱 전략의 패스워드를 지원할 수 있다는 장점이 있습니다.

~~~
@Bean
public PasswordEncoder passwordEncoder() {
    // Spring Security 5 권장하는 인코더
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}

@Service
public class AccountService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    public AccountService(
            PasswordEncoder passwordEncoder
    ) {
        this.passwordEncoder = passwordEncoder;
    }

    ...

    public Account save(Account account) {
        account.encodePassword(passwordEncoder);
        return accountRepository.save(account);
    }
}

@Entity
public class Account {
    ...

    public void encodePassword(PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(this.password);
    }
}

결과 - 

{
    id: 1,
    username: "asd",
    password: "{bcrypt}$2a$10$JwEOVmVJKZQA84K.tSjZRu/7arq/UJsLdP/mjCBqxF99UC3Kq0xrK",
    role: "ADMIN"
}
~~~

Spring Security 5 권장하는 인코더 PasswordEncoderFactories 사용하여 정상적으로 인코더 하였습니다.

# Spring Security Test Code

- RequestPostProcessor를 사용해서 테스트 하는 방법
    - with(user(“user”))
    - with(anonymous())
    - with(user(“user”).password(“123”).roles(“USER”, “ADMIN”))
    - 자주 사용하는 user  객체는 리팩토리으로 빼내서 재사용 가능.

- 애노테이션을 사용하는 방법
    - @WithMockUser
    - @WithMockUser(roles=”ADMIN”)
    - 커스텀 애노테이션을 만들어 재사용 가능.

- Test Code 상에서 DATA DB 변경, 접근 사항이 있다면
    - @Transactional 어노테이션을 붙여주어 독립적인 테스트로 만들어주면 좋습니다.
    - 클레스 전체 Test 실행시 사용자 추가가 중복으로 일어나므로 해당 메소드의 결과값을 초기화 하는것입니다.

의존성 추가

~~~
testImplementation('org.springframework.security:spring-security-test')
~~~

Test Code

~~~
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;

    /**
     * 일반적인 익명의 접근의 Test
     *
     * @WithAnonymousUser == with(anonymous())
     */
    @Test
    // @WithAnonymousUser 어노테이션을 활용한 익명의 user 접근
    public void index_annoymous() throws Exception {
        mockMvc
                .perform(get("/").with(anonymous()))
                .andExpect(status().isOk())
                .andDo(print());
    }

    /**
     * user -> user
     * <p>
     * 특정 Role 값을 가지고있는 접근 Test
     * with( user() ) 를 사용합니다. user() 는 spring security test 에서 제공하는 메소드 입니다.
     * 가상의 user 를 만들어 요청하는 방법입니다.
     *
     * @WithMockUser(username = "", roles = "") == with(user("jjunpro").roles("USER"))
     */
    @Test
    // @WithMockUser(username = "jjunpro", roles = "USER") 어노테이션을 활용한 user 접근
    public void index_user() throws Exception {
        mockMvc
                .perform(get("/").with(user("jjunpro").roles("USER")))
                .andExpect(status().isOk())
                .andDo(print());
    }

    /**
     * user -> admin
     * <p>
     * admin 페이지에 user 권한이 접근하는 경우
     * 권한이 맞지않으므로 403 error forbidden 발생합니다.
     */
    @Test
    public void admin_user() throws Exception {
        mockMvc
                .perform(get("/admin").with(user("jjunpro").roles("USER")))
                .andExpect(status().isForbidden())
                .andDo(print());
    }

    /**
     * admin -> admin
     * <p>
     * admin 페이지에 admin 권한이 접근하는 경우
     * 200 접근 성공입니다.
     */
    @Test
    // @WithMockUser(username = "jjunpro", roles = "ADMIN") 어노테이션을 활용한 admin 접근
    public void admin_admin() throws Exception {
        mockMvc
                .perform(get("/admin").with(user("jjunpro").roles("ADMIN")))
                .andExpect(status().isOk())
                .andDo(print());
    }
}
~~~

가상의 유저정보를 어노테이션으로 만들때 `중복으로 코드`를 작성해야 하는경우 
`커스텀 어노테이션`을 따로 만들어서 적용하면 됩니다.

~~~
@Retention(RetentionPolicy.RUNTIME)
@WithMockUser(username = "jjunpro", roles = "USER")
public @interface WithUser { }

@Test
@WithUser
public void index_user() throws Exception {
    mockMvc
            .perform(get("/"))
            .andExpect(status().isOk())
            .andDo(print());
}
~~~
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
- [4. Spring Security Test Code](#Spring-Security-Test-Code)
     - [1. Form Login 테스트](#Form-Login-테스트)
- [5. SecurityContextHolder와 Authentication](#SecurityContextHolder와-Authentication)
    
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

## Form Login 테스트

~~~
/**
    * @Transactional 해당 메소드의 테스트가 끝나면 초기화해줍니다.
    *
    * formLogin() 메소드로 로그인을 시도하고
    * authenticated() 인증 상태를 체크합니다.
    */
@Test
@Transactional
public void login() throws Exception {
    // 새로운 유저정보를 DB 에 등록합니다.
    String username = "user";
    String password = "1234";
    this.createUser(
            username,
            password
    );

    mockMvc
            .perform(formLogin()
                    .user(username)
                    .password(password))
            .andExpect(authenticated())
            .andDo(print());
}

private Account createUser(
        String username,
        String password
) {
    Account account = new Account();
    account.setUsername(username);
    account.setPassword(password);
    account.setRole("USER");

    accountService.save(account);

    return account;
}
~~~

# SecurityContextHolder와 Authentication

- Authentication
    - Principal과 GrantAuthority 제공.

- Principal
    - “누구"에 해당하는 정보. 
    - UserDetailsService에서 리턴한 그 객체.
    - 객체는 UserDetails 타입.

- GrantAuthority: 
    - “ROLE_USER”, “ROLE_ADMIN”등 Principal이 가지고 있는“권한”을 나타낸다.
    - 인증 이후, 인가 및 권한 확인할 때 이 정보를 참조한다.

- UserDetails
    - 애플리케이션이 가지고 있는 유저 정보와 스프링 시큐리티가 사용하는Authentication 객체 사이의 어댑터.
    - UserDetailsService
    - 유저 정보를 UserDetails 타입으로 가져오는 DAO (Data Access Object) 인터페이스.


사용자가 애플리케이션에서 인증을 거치고 나면 `인증된 사용자 정보(Principal)를 Authentication 객체 내부에 담아서 관리`를 하고 
Authentication 객체를 SecurityContext 다음 SecurityContextHolder 담아서 가지고 있습니다.

SecurityContextHolder 객체는 SecurityContext를 제공해주는데 기본적인 방법이 ThreadLocal을 사용하는 것입니다.
ThreadLocal은 한 Thread 내에서 공유하는 저장소 
그러면 애플리케이션 어디서나 접근이 가능합니다.
SecurityContextHolder는 하나의 Thread에 특화되어 있으므로 만약 Thread가 달라질경우 Authentication값을 가져올 수 없습니다.

서블릿 기반의 웹 애플리케이션은 어떠한 요청이 들어올경우 처리되는 Thread는 명시적으로 비동기적으로 사용하지 않는 이상 동일한 Thread가 작업을 처리하게 됩니다. Servlet Container 기본적인 동작 방법입니다. 하나의 Request 마다 하나의 Thread 를 사용한다.
그렇다고해서 요청이 들어올때마다 새로운 Thread를 만드는 것이 아닌 
어떠한 요청을 Servlet 톰켓이 받았을 때 어떠한 Thread에 배정하는 지는 Connect 톰켓이 하는일이고 최종적으로 애플리케이션 내부로 들어오면서 로직이 실행될때는 대부분 하나의 Thread가 담당하게 됩니다.

그러면 principal 값을 매개변수로 넘겨주고 받아서 사용할 필요없이 SecurityContextHolder 통해서 값을 가져와서 확인할 수 있습니다.

~~~
@Service
public class SampleService {

    // 현재 로그인한 사용자 정보를 참조할 때
    public void dashboard() {
        System.out.println("dashboard");
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();

        // 인증이 완료된 사용자의 정보
        Object principal = authentication.getPrincipal();

        // 사용자가 가지고 있는 권한을 나타냅니다. 권한은 ADMIN, USER ... 등등 여러개일수도 있으니 Collection
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // 인증이 완료된 사용자인지 판별합니다.
        boolean authenticated = authentication.isAuthenticated();
    }
}
~~~

각각의 정보에 디버그를 찍어서 확인하면 어떠한 값이 들어가나 확인할 수 있습니다.

디버그 정보의 
authentication 타입을 확인하면 여러개의 구현체가 존재합니다.
FormLogin 의 경우 UsernamePasswordAuthenticationToken 으로 return 되어 있습니다.

최종적으로 SecurityContextHolder 내부에 Authentication 형식으로 담기는 것입니다.

SecurityContextHolder 내부에는 필수로 인증이 완료된 정보만 저장이 됩니다.

Authentication 내부에는 principal 그리고 GrantAuthority 정보가 들어있습니다.

~~~
@Service
public class AccountService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User
                .builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }
~~~

principal 타입은 User 입니다.
UserDetailsService 타입의 구현체에서 return User 가 principal 입니다.

authorities 값은 1개만 존재하는것을 확인할 수 있습니다.
"ROLE_USER" 해당 정보도 UserDetailsService 구현할때 정보를 주었습니다.
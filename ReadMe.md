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
- [6. AuthenticationManager와 Authentication](#AuthenticationManager와-Authentication)
    - [1. AuthenticationManager 인증 과정](#AuthenticationManager-인증-과정)
- [7. ThreadLocal](#ThreadLocal)
- [8. Authentication과 SecurityContextHodler](#Authentication과-SecurityContextHodler)
- [9. 스프링 시큐리티 Filter와 FilterChainProxy](#스프링-시큐리티-Filter와-FilterChainProxy)
- [10. DelegatingFilterProxy와 FilterChainProxy](#DelegatingFilterProxy와-FilterChainProxy)
- [11. 인증,체인,필터 최종 정리](#인증,체인,필터-최종-정리)
- [12. AccessDecisionManager](#AccessDecisionManager)
    - [1. accessDecisionManager 설정](#accessDecisionManager-설정)
    - [2. expressionHandler 설정](#expressionHandler-설정)
- [13. 최종 정리](#최종-정리)
    - [1. 인증](#인증)
    - [2. 인증체크](#인증체크)
- [14. ignoring 필터 제외](#ignoring-필터-제외)
- [15. WebAsyncManagerIntegrationFilter](#WebAsyncManagerIntegrationFilter)
- [16. @Async](#@Async)
- [17. SecurityContextPersistenceFilter](#SecurityContextPersistenceFilter)
- [18. HeaderWriterFilter](#HeaderWriterFilter)
- [19. CSRF 어택 방지 필터 CsrfFilter](#CSRF-어택-방지-필터-CsrfFilter)
- [20. CSRF 토큰 사용 예제](#CSRF-토큰-사용-예제)
     - [1. CSRF Test Code](#CSRF-Test-Code)
- [21. LogoutFilter](#LogoutFilter)

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

Authentication 정보를 담고있는 저장소 인터페이스

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

# AuthenticationManager와 Authentication

Authentication 정보를 만들고 인증을 처리하는 인터페이스 

AuthenticationManager 내부에는 authenticate 메소드 하나만 존재합니다.

Authentication authenticate(Authentication authentication) 전달 인자로 받은 `Authentication 객체가 인증 정보`를 담고있습니다.

authentication 값이 유효한지 확인 후 유효하다면 인증된 UserDetailsService 가 return 한 principal 정보를 담고있는 authenticate 객체를 return 합니다.

`비밀번호가 잘못되었다면` BadCredentialsException 발생
`계정이 잠겨있다면` LockedException 발생
`계정이 비활성화 되어있다면` DisabledException 발생

AuthenticationManager 구현체로는 보통 `ProviderManager.class`를 사용합니다.

인증과정을 살펴보기 위해서 ProviderManager.class 의 authenticate() 메소드에 디버거를 찍습니다.

인자로 받은 Authentication authentication 객체에는 
Client 에서 전달받은 principal 값과 credentials 값을 전달 받았습니다.
2개의 전달받은 값으로 인증을 시작해야 합니다.

## AuthenticationManager 인증 과정

~~~
ProviderManager.class

for (AuthenticationProvider provider : getProviders()) {

    // F7 눌러 적용된 프로바이더를 확인합니다.
    if (!provider.supports(toTest)) {
        continue;
    }
    ...
}
~~~

ProviderManager.class 가 직접 인증을 하는것이 아니라
다른 `AuthenticationProvider 에게 위임`을 해서
`여러개의 provider 를 사용해서 인증`을 합니다.

ProviderManager.class 의 AuthenticationProvider 로 단 하나의 익명 사용자를 인증하는 `AnonymousAuthenticationProvider 를 가지고 있습니다.`
이는 Client 에서 전달해준 Authentication authentication 값의 실제 `UsernamePasswordAuthenticationToken.class 를 처리할 수 있는 provider 가 아니므로 그냥 넘어갑니다.`

최종적으로 `ProviderManager.class 내부에는 UsernamePasswordAuthenticationToken.class 를 처리할 수 있는 provider 가 존재하지 않습니다.`

~~~
ProviderManager.class

if (result == null && parent != null) {
    // Allow the parent to try.
    try {
        result = parentResult = parent.authenticate(authentication);
    }
    ...
}
~~~

현재 ProviderManager에게 처리 할수 있는 Provider가 존재하지 않을경우 `ProviderManager의 Parent에게 위임한다.`
이런경우 parent.authenticate 로 가게됩니다.

~~~
ProviderManager.class

for (AuthenticationProvider provider : getProviders()) {
    // F7 눌러 적용된 프로바이더를 확인합니다.
    if (!provider.supports(toTest)) {
        continue;
    }
}
~~~

다시한번 전달받은 authentication `타입과 맞는 Provider 가 존재하는지 탐색` 합니다. 이번엔 `UsernamePasswordAuthenticationToken 타입의 Provider 를 찾았습니다.`

~~~
ProviderManager.class

// F7 눌러 적용된 프로바이더를 확인합니다.
result = provider.authenticate(authentication);
~~~

`AbstractUserDetailsAuthenticationProvider`
해당 Provider 의 인증을 호출합니다.
`UserDetailsService 를 사용해서 인증을 해주는 Provider` 입니다.

~~~
AbstractUserDetailsAuthenticationProvider.class

try {
    // F7 눌러 해당 클래스로 들어갑니다.
    user = retrieveUser(username,
            (UsernamePasswordAuthenticationToken) authentication);
}
~~~

`retrieveUser 매소드에서 우리가 구현한 UserDetailsService 로 연결`이 됩니다.
DaoAuthenticationProvider.class 로 연결이 됩니다.

~~~
DaoAuthenticationProvider.class

protected final UserDetails retrieveUser() {
    try {
        // F7 눌러 해당 클래스로 들어갑니다.
        UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
    }
    ...
}
~~~

DaoAuthenticationProvider.class 가지고있는 `getUserDetailsService 값은 개발자가 구현한 UserDetailsService 의 구현체 (AccountService)` 입니다.
결론은 드디어 `개발자가 구현한 코드로 연결이 되는 구간`입니다.

~~~
AbstractUserDetailsAuthenticationProvider.class

try {
    preAuthenticationChecks.check(user);
    additionalAuthenticationChecks(user,
            (UsernamePasswordAuthenticationToken) authentication);
}
~~~

다음 유저의 계정이 잠겨있는지 등등 계정의 상태를 체크하는 구간입니다.

이제 디버그 결과값을 확인해 봅니다.
`사용자가 전달한 authentication 값은 문자열`로 저장이 되어있었습니다.
인증이 위와같은 진행 되면서 `result 값의 authentication 를 확인하면 개발자가 UserDetailsService 구현체로 구현한 User 객체로 구현`이 되어있을것을 확인합니다.

# ThreadLocal

하나의 Thread 내에서 변수..등등 자원 을 공유하는 것

- Java.lang 패키지에서 제공하는 쓰레드 범위 변수. 즉, 쓰레드 수준의 데이터 저장소.
    - 같은 쓰레드 내에서만 공유.
    - 따라서 같은 쓰레드라면 해당 데이터를 메소드 매개변수로 넘겨줄 필요 없음.
    - `SecurityContextHolder의 기본 전략.`

간단예제

~~~
public class AccountContext {

    // Account 를 저장할 수 있는 ThreadLocal 하나 만듭니다.
    private static final ThreadLocal<Account> ACCOUNT_THREAD_LOCAL = new ThreadLocal<>();

    // ThreadLocal 내부에 저장하는 메소드
    public static void setAccount(Account account) {
        ACCOUNT_THREAD_LOCAL.set(account);
    }

    // ThreadLocal 내부에 저장된 정보를 가져오는 메소드
    public static Account getAccount() {
        return ACCOUNT_THREAD_LOCAL.get();
    }
}

@Controller
public class SampleController {

    private final SampleService sampleService;
    private final AccountRepository accountRepository;

    @GetMapping("/dashboard")
    public String dashboard(
            Model model,
            Principal principal
    ) {
        // 등록된 유저의 Account 정보를 조회 후 ThreadLocal 에 저장하였습니다.
        AccountContext.setAccount(accountRepository.findByUsername(principal.getName()));

        sampleService.dashboard();

        return "dashboard";
    }
}

@Service
public class SampleService {

    public void dashboard() {
        // ThreadLocal을 사용하여 메소드 파라미터를 받지 않아도 유저의 정보를 가져와서 사용하였습니다.
        Account account = AccountContext.getAccount();
        System.out.println(account.getUsername());
    }
}
~~~

# Authentication과 SecurityContextHodler

AuthenticationManager가 인증을 마친 뒤 리턴 받은 Authentication 객체의 행방은?

- UsernamePasswordAuthenticationFilter
    - 폼 인증을 처리하는 시큐리티 필터
    - 인증된 Authentication 객체를 SecurityContextHolder에 넣어주는 필터
    - SecurityContextHolder.getContext().setAuthentication(authentication)

- SecurityContextPersisenceFilter
    - SecurityContext를 HTTP session에 캐시(기본 전략)하여 여러 요청에서 Authentication을 공유할 수 있 공유하는 필터.
    - SecurityContextRepository를 교체하여 세션을 HTTP session이 아닌 다른 곳에 저장하는 것도 가능하다.

dashboard 페이지에 접근하면 로그인 페이지가 출력됩니다.
user 의 계정으로 로그인을 한 후 새로고침 후 다시 dashboard 페이지에 접근하면 로그인페이지가 나오지않고
user 가 로그인한 이전 인증이 완료된 Authentication 정보를 체크후 바로 접근가능하게 해줍니다.

~~~
public void dashboard() {
    Authentication authentication = SecurityContextHolder
            .getContext()
            .getAuthentication();

    System.out.println("====authentication====");
    System.out.println(authentication);
}

첫번째 로그인 후 접근시 authentication 정보의 주소 값
====authentication====
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@ed00933c:

두번째 새로고침 후 접근시 authentication 정보의 주소 값
====authentication====
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@ed00933c:
~~~

둘의 주소값은 동일합니다.

# 스프링 시큐리티 Filter와 FilterChainProxy

~~~
FilterChainProxy.class

private List<Filter> getFilters(HttpServletRequest request) {

디버그 > for (SecurityFilterChain chain : filterChains) {
            if (chain.matches(request)) {
                return chain.getFilters();
            }
        }

    return null;
}
~~~

SecurityFilterChain 의 특정한 요청이 매치가 되면 해당되는 필터를 가져와서 사용합니다.

- 스프링 시큐리티가 제공하는 필터들
    - WebAsyncManagerIntergrationFilter
    - SecurityContextPersistenceFilter
    - HeaderWriterFilter
    - CsrfFilter
    - LogoutFilter
    - UsernamePasswordAuthenticationFilter
    - DefaultLoginPageGeneratingFilter
    - DefaultLogoutPageGeneratingFilter
    - BasicAuthenticationFilter
    - RequestCacheAwareFtiler
    - SecurityContextHolderAwareReqeustFilter
    - AnonymouseAuthenticationFilter
    - SessionManagementFilter
    - ExeptionTranslationFilter
    - FilterSecurityInterceptor

이 모든 필터는 FilterChainProxy가 호출한다.

`위 SecurityFilterChain 필터의 목록이 만들어지고 커스텀 마이징하는 장소는 개발자가 만든 SecurityConfig.class 입니다.`

~~~
SecurityConfig.class

@Configuration
// @EnableWebSecurity Spring Boot 에서 자동 등록을 해주므로 생략 가능
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .formLogin()
                .and()
                .httpBasic();
    }
}
~~~

사용자의 커스텀 `SecurityConfig 자체가 Filter` 가 되는겁니다.
그렇다는것은 여러개의 Filter를 제작 가능하다는 것입니다.

SecurityFilterChain 목록이 추가가 되고 해당 Filter 에 맞는 정보를 매치해서 적용을 합니다.

간단 예제

~~~
/**
 * 모든 요청이 인증 없이 접근을 허용하는 Config
 * */
@Configuration
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

/**
 * account 요청만 인증 없이 접근을 허용하는 Config
 */
@Configuration
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
~~~

디버그 모드로 실행하면 filterChains 은 등록한 config의 2개가 출력되고
우선순위 1위 의 모든 요청을 허용하는 AllAuthConfig 를 먼저 실행 합니다. 

둘의 filter 정보를 보면 갯수가 다릅니다.

AllAuthConfig 설정은 form 인증 httpbasic 설정이 존재해서 Filter 정보가 더 많이 존재하는 것입니다.
결론은 `사용자의 설정에 따라서 Filter 의 목록은 달라집니다.`

Filter 접근 순서를 @Order 로 설정하는 것 보다는 
antMatcher("") 메소드로 직접 명시적으로 설정하는게 좋습니다.

~~~
FilterChainProxy.class

private void doFilterInternal(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {

    // Filter 목록들을 가져옵니다.
    List<Filter> filters = getFilters(fwRequest);

    if (filters == null || filters.size() == 0) {

        // chain 정보를 가지고
        chain.doFilter(fwRequest, fwResponse);

    }

    // VirtualFilterChain 객체 내부로 값을 전송합니다.
    VirtualFilterChain vfc = new VirtualFilterChain(fwRequest, chain, filters);
    vfc.doFilter(fwRequest, fwResponse);
}
~~~

# DelegatingFilterProxy와 FilterChainProxy

사용자가 요청을 보내면 Servlet 기반의 애플리케이션 이기때문에 ServletContainer 가 정보를 받습니다.
개발자가 사용하는 ServletContainer 는 Tomcat 입니다.
ServletContainer 는 Servlet Spec 을 지원합니다.

Servlet Spec 에는 Filter 라는 개념이 있습니다.

- DelegatingFilterProxy
    - 일반적인 서블릿 필터.
    - 서블릿 필터 처리를 `스프링에 들어있는 빈으로 위임하고 싶을 때 사용`하는 서블릿 필터.
    - 타겟 빈 이름을 설정한다.
    - 스프링 부트 없이 스프링 시큐리티 설정할 때는 AbstractSecurityWebApplicationInitializer를 사용해서 등록.
    - 스프링 부트를 사용할 때는 자동으로 등록 된다. (SecurityFilterAutoConfiguration)

- FilterChainProxy
    - 보통 “springSecurityFilterChain” 이라는 이름의 빈으로 등록된다.

DelegatingFilterProxy.class 가 Spring Bean 으로 등록되어 있는 FilterChainProxy 에게 작업을 위임 하려면 Bean의 이름을 알아야 합니다.
그 이름은 보통 springSecurityFilterChain 입니다.
이름을 확인하는 방법은 SecurityFilterAutoConfiguration.class 의 DEFAULT_FILTER_NAME 으로 등록되있는것을 확인하면 됩니다.

~~~
public class SecurityFilterAutoConfiguration {

	private static final String DEFAULT_FILTER_NAME = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME;

	@Bean
	@ConditionalOnBean(name = DEFAULT_FILTER_NAME)
	public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration(
			SecurityProperties securityProperties) {
		DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean(
				DEFAULT_FILTER_NAME);
		registration.setOrder(securityProperties.getFilter().getOrder());
		registration.setDispatcherTypes(getDispatcherTypes(securityProperties));
		return registration;
	}
...
~~~

# 인증,체인,필터 최종 정리

SecurityContextHolder 가 Authentication 정보를 가지고 있습니다.

AuthenticationManager 가 Authentication 의 정보를 가지고 인증을 합니다.
인증된 Authentication 정보를 다시 SecurityContextHolder 내부에 넣어줍니다.
넣는 과정에서 여러가지 Filter 들이 실행이 됩니다.

이러한 여러가지 Filter 들은 FilterChainProxy 가 호출을 해줍니다.

FilterChainProxy 는 DelegatingFilterProxy 를 통해서 접근을 합니다.

# AccessDecisionManager

이미 인증이 완료된 사용자가 특정한 서버의 리소스에 접근을 할때 유효한 요청인지 판단하는 AccessDecisionManager.interface

- Access Control 결정을 내리는 인터페이스로, `구현체 3가지를 기본으로 제공`한다.
    - AffirmativeBased: 여러 Voter중에 `한명이라도 허용하면 허용.` 기본 전략.
    - ConsensusBased: 다수결
    - UnanimousBased: 만장일치

- AccessDecisionVoter
    - 해당 Authentication이 특정한 Object에 접근할 때 필요한 ConfigAttributes를 만족하는지 확인한다.
    - WebExpressionVoter: 웹 시큐리티에서 사용하는 기본 구현체, ROLE_Xxxx가 매치하는지 확인.
    - RoleHierarchyVoter: 계층형 ROLE 지원. ADMIN > MANAGER > USER

~~~
AffirmativeBased.class

for (AccessDecisionVoter voter : getDecisionVoters()) {
        // F7 눌러 해당 클래스로 들어갑니다.
디버그 > int result = voter.vote(authentication, object, configAttributes);
        // result 값이 1 이면 허용입니다.
}
~~~

디버그 후 실행하면 voter 값이 하나가 존재합니다.
expressionHandler

~~~
WebExpressionVoter.class

// weca 값에는 premitAll 값이 들어왔습니다.
WebExpressionConfigAttribute weca = findConfigAttribute(attributes); 

// expressionHandler 메소드로 지원하는지 여부를 파악 후 return 합니다.
EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication,
				fi);
~~~

~~~
AffirmativeBased.class

// result = 1 입니다.
switch (result) {
case AccessDecisionVoter.ACCESS_GRANTED:
    return;

case AccessDecisionVoter.ACCESS_DENIED:
    deny++;

    break;
~~~

식으로 검증을 합니다.

User.html 페이지가 있습니다.
해당 페이지의 권한은 USER ROLE 만 접근이 가능합니다.
ADMIN 권한이 접근하는 경우 Spring Security는 ADMIN 권한이 모든 권한을 가지고 있다고 인식하지 못해서
User.html 페이지에 접근을 못합니다.

AccessDecisionManager 활용하여 ADMIN 권한을 모든 권한에 접근하도록 설정하겠습니다.

## accessDecisionManager 설정

~~~
SecurityConfig.class

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

http
    .authorizeRequests()
    .anyRequest()
    .authenticated()
    // accessDecisionManager 추가하는 위치
    .accessDecisionManager(accessDecisionManager());
~~~

## expressionHandler 설정

~~~
SecurityConfig.class

public SecurityExpressionHandler securityExpressionHandler() {
    // roleHierarchy
    RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
    roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER ");

    // DefaultWebSecurityExpressionHandler
    DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
    handler.setRoleHierarchy(roleHierarchy);

    return handler;
}

http
    .authorizeRequests()
    .anyRequest()
    .authenticated()
    .expressionHandler(securityExpressionHandler());
~~~

AccessDecisionManager 자체를 커스텀 한것이 아니라 Voter 가 사용하는 DefaultWebSecurityExpressionHandler 만 커스텀 한것입니다.

# FilterSecurityInterceptor

AccessDecisionManager를 사용하여 Access Control 또는 예외 처리 하는 필터.
대부분의 경우 FilterChainProxy에 제일 마지막 필터로 들어있다.

인증이 완료된 상태에서 최종적으로 리소스에 접근하는 마지막에 체크하는 Filter

# ExceptionTranslationFilter

필터 체인에서 발생하는 AccessDeniedException과 AuthenticationException을 처리하는 필터

FilterSecurityInterceptor 상위 클래스인 AbstractSecurityInterceptor 에서 발생한 Exception 처리를 합니다.

- AuthenticationException 발생 시
    - AuthenticationEntryPoint 실행
    - AbstractSecurityInterceptor 하위 클래스(예, FilterSecurityInterceptor)에서 발생하는 예외만 처리.
    - 그렇다면 UsernamePasswordAuthenticationFilter에서 발생한 인증 에러는 ExceptionTranslationFilter 내부에서 관리하지 않고 UsernamePasswordAuthenticationFilter 내부에서 관리합니다.

- AccessDeniedException 발생 시
    - 익명 사용자라면 AuthenticationEntryPoint 실행 사용자가 인증을 하도록 로그인페이지로 유도
    - 익명 사용자(이미 인증된 사용자)가 아니면 AccessDeniedHandler에게 위임

~~~
ExceptionTranslationFilter.class

디버그 > if (exception instanceof AuthenticationException) {
    logger.debug(
            "Authentication exception occurred; redirecting to authentication entry point",
            exception);

    sendStartAuthentication(request, response, chain,
            (AuthenticationException) exception);
}
~~~

새로운 유저 정보를 생성 후 url/dashboard 접근합니다.
디버그에 체크한 exception 걸리게 됩니다.

url/dashboard 는 Authentication 인증이 완료된 사용자만 접근이 가능한 url 입니다.
그러므로 AccessDeniedException 발생하여 AuthenticationEntryPoint 실행 후 로그인 페이지로 유도합니다.

~~~
else if (exception instanceof AccessDeniedException) {
    // 유저의 정보를 확인합니다.
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
~~~

# 최종 정리

ServletContainer 로 요청이 들어오면 Servlet Filter 목록 중에서 `DelegatingFilterProxy` 가 있습니다.
DelegatingFilterProxy 가 Spring Boot를 사용하면 자동으로 등록이 되고 (만약 자동등록이 되지않으면 AbstractSecurityWebApplicationInitializer를 사용해서 등록하면 됩니다.)
DelegatingFilterProxy 는 특정한 `FilterChainProxy Bean 이름(“springSecurityFilterChain”) 으로 Filter 처리를 위임`을 합니다.

`FilterChainProxy 내부에는 Security Filter 목록`을 가지고 있습니다.
[SecurityContextPersistenceFilter, UsernamePasswordAuthenticationFilter, FilterSecurityInterceptor, ...]

이러한 `Security Filter 목록은 WebSecurity 로 만들어 집니다.`
WebSecurityConfigurerAdapter 상속받아 구현하는 WebSecurity 를 만들면 FilterChain 을 만드는 겁니다.

~~~
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter { ... }
~~~

이러한 Filter 들을 사용하는 객체들이 존재합니다.

## 인증

인증 관련해서는 AuthenticationManager.interface 를 사용하며 구현체로는 ProviderManager.class 를 많이 사용합니다.

ProviderManager 같은경우에는 다른 AuthenticationProvider 를 사용해서 인증을 처리합니다.
그중 하나가 DaoAuthenticationProvider 입니다.

DaoAuthenticationProvider 의 역할
UserDetailsService.interface 를 사용해서 DATA DB 에서 읽어온 User 정보를 사용해서 사용자가 입력한 정보와 같은지 확인 후 인증을 합니다.

인증 정보가 확인이 된다면 SecurityContextHolder 내부에 저장합니다.
그러면 애플리케이션 전반에서 사용합니다.

- SecurityContextHolder 
    - SecurityContext
        - Authentication
            - Principal
            - GrantAuthority

## 인증체크

인증체크는 FilterSecurityInterceptor 가 AccessDecisionManager 사용해서 인가처리(인증체크)를 합니다.
인증체크: SecurityContextHolder 내부에 들어있는 Authentication 정보가 사용자가 접근하려는 리소스에 적절한 ROLE(권한) 을 가지고 있는지 체크합니다.

확인하는 방법은 3개가 존재하지만 기본적으로는 AffirmativeBased 를 기본전략으로 사용합니다.

AffirmativeBased 가 사용하는 Voter 중에서 WebExpressionVoter 하나만 사용하고 있습니다.
계층형 권한 형태를 커스텀하기 위해서 사용하는 SecurityExpressionHandler

# ignoring 필터 제외

지금까지 살펴본 모든 요청은 Spring Security 가 Filter 들을 적용해서 처리를 해왔습니다.

정적이 리소스들을 제외하는 방법
사용자가 웹페이지에 요청을 할때 크롬 개발자 탭에서 Network 탭에서 넘어가는 정보를 보면
localhost-200, favion.ico-302, login-200 으로 3개의 전송이 된것을 확인할 수 있습니다.
이는 불필요한 전송이 2개나 포함되어 있는데 SecurityConfig 내부 설정에서 favion.ico 접근 설정이 없기 때문에 anyRequest().authenticated() 설정으로 빠지므로 
인증페이지로 연결이 되는것입니다.

~~~
public class SecurityConfig extends WebSecurityConfigurerAdapter {
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
                .hasRole("ADMIN")
                .mvcMatchers("user")
                .hasRole("USER");

        http
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .expressionHandler(securityExpressionHandler());
    }
}
~~~

어떠한 요청을 Filter 적용을 제외시키는 설정은 WebSecurity 를 사용하면 됩니다.

~~~
이런 방법의 제외 방법도 있지만 권장하지 않습니다.
해당 방법으로 제외하면 authorizeRequests 설정으로 등록된 Filter를 전부 적용은 받습니다.
http
    .authorizeRequests()
    .requestMatchers(PathRequest
        .toStaticResources()
        .atCommonLocations());

@Override
public void configure(WebSecurity web) throws Exception {
    // 기본 제외 방법
    web.ignoring().mvcMatchers("/favicon.ico");

    // Spring 프레임워크 제외방법
    // 스프링 부트가 제공하는 PathRequest를 사용해서 정적 자원 요청을 스프링 시큐리티 필터를 적용하지 않도록 설정.
    web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
}
~~~

# WebAsyncManagerIntegrationFilter

Filter 중에서 가장 최상위에 있는 Async 웹 MVC를 지원하는 필터 WebAsyncManagerIntegrationFilter

SecurityContext 는 ThreadLocal 로 동작하기 때문에 동일한 Thread 에서만 SecurityContext 가 공유가 됩니다.

하지만 Async 기능 에서는 다른 Thread 를 사용하게 됩니다.
다른 Thread 이지만 동일한 SecurityContext 를 사용할 수 있도록 지원해주는 WebAsyncManagerIntegrationFilter 입니다.

- 스프링 MVC의 Async 기능(핸들러에서 Callable을 리턴할 수 있는 기능)을 사용할 때에도 SecurityContext를 공유하도록 도와주는 필터.
    - PreProcess: SecurityContext를 설정한다.
    - Callable: 비록 다른 쓰레드지만 그 안에서는 동일한 SecurityContext를 참조할 수 있다.
    - PostProcess: SecurityContext를 정리(clean up)한다.

# @Async

Async Service 호출

~~~
SampleController.class

@GetMapping("/async-service")
public String asyncService() {
    sampleService.asyncService();
    return "async-service";
}
~~~

~~~
SampleService.class

/**
* @Async 어노테이션을 붙이면 특정 Bean 안의 메소드를 호출할 때 별도의 Thread 를 만들어서 비동기적으로 호출을 해줍니다.
* */
@Async
public void asyncService() {
    System.out.println("Async service");
}
~~~

~~~
ProjectApplication.class

@EnableAsync
public class ProjectApplication { ... }
~~~

~~~
SecurityConfig.class

@Override
protected void configure(HttpSecurity http) throws Exception {
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
~~~

[참고](https://docs.oracle.com/javase/7/docs/api/java/lang/InheritableThreadLocal.html)

# SecurityContextPersistenceFilter

요청간의 SecurityContext를 공유할 수 있는 기능을 제공합니다.
예를들어 로그인을 한 후 인증이 필요한 페이지에 접근하면 접근이 됩니다.
다음 새로고침 후 접근하면 SecurityContext 간의 정보가 공유가 되기 때문에 인증 필요없이 접근합니다.

- SecurityContextRepository를 사용해서 기존의 SecurityContext를 읽어오거나 초기화 한다.
    - 기본으로 사용하는 전략은 HTTP Session을 사용한다.
    - Spring-Session과 연동하여 세션 클러스터를 구현할 수 있다.

SecurityContextRepository.interface 의 기본 구현체는 HttpSessionSecurityContextRepository.class 입니다.

커스텀한 인증 필터를 만드는 경우에는 SecurityContextPersistenceFilter 뒤쪽에 등록을 해줘야 합니다.

# HeaderWriterFilter

- 응답 헤더에 시큐리티 관련 헤더를 추가해주는 필터
    - XContentTypeOptionsHeaderWriter: 마임 타입 스니핑 방어.
    - XXssProtectionHeaderWriter: 브라우저에 내장된 XSS 필터 적용.
    - CacheControlHeadersWriter: 캐시 히스토리 취약점 방어. (민감한 정보가 캐시로 남지 않도록 삭제합니다.)
    - HstsHeaderWriter: HTTPS로만 소통하도록 강제.
    - XFrameOptionsHeaderWriter: clickjacking 방어. (다른 사이트로 연결되는 링크가 웹에 못들어오도록 막습니다.)

~~~
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Language: en-US
Content-Type: text/html;charset=UTF-8
Date: Sun, 04 Aug 2019 16:25:10 GMT
Expires: 0
Pragma: no-cache
Transfer-Encoding: chunked
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
~~~

- X-Content-Type-Options:
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
- Cache-Control:
    - https://www.owasp.org/index.php/Testing_for_Browser_cache_weakness_(OTG-AUTHN-006)
- X-XSS-Protection
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
    - https://github.com/naver/lucy-xss-filter
- HSTS
    - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- X-Frame-Options
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    - https://cyberx.tistory.com/171

# CSRF 어택 방지 필터 CsrfFilter

원치않는 요청을 임의대로 만들어서 보내는것 

나의 브라우저 -> 은행에 로그인 -> 유튜브(나쁜사이트)로 접근하면 아무런 이상없는 홈페이지 같지만 해당 홈페이지는 악의적인 코드가 심어져 있습니다. 평범한 Form 처럼 보이지만 실제로는 은행으로 요청을 보내는 Form 입니다.

- CSRF 토큰 인증으로 접근하는경우
    - 나의 브라우저 -> 은행에 로그인 -> 은행으로 요청을 보내는 나쁜사이트가 접근합니다. 하지만 나쁜 사이트는 CSRF 토큰이 존재하지 않으므로 접근을 막습니다.

- CSRF 어택 방지 필터
    - 인증된 유저의 계정을 사용해 악의적인 변경 요청을 만들어 보내는 기법.
    - https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
    - https://namu.wiki/w/CSRF
    - CORS를 사용할 때 특히 주의 해야 함.
        - 타 도메인에서 보내오는 요청을 허용하기 때문에...
        - https://en.wikipedia.org/wiki/Cross-origin_resource_sharing

- 의도한 사용자만 리소스를 변경할 수 있도록 허용하는 필터
    - CSRF 토큰을 사용하여 방지.

~~~
CsrfFilter.class

CSRF 토큰을 생성 후 보냅니다.
request.setAttribute(CsrfToken.class.getName(), csrfToken);
request.setAttribute(csrfToken.getParameterName(), csrfToken);
...

CSRF 토큰값을 받아옵니다.
String actualToken = request.getHeader(csrfToken.getHeaderName());
if (actualToken == null) {
    actualToken = request.getParameter(csrfToken.getParameterName());
}

CSRF 토큰값이 일치하는지 확인합니다.
if (!csrfToken.getToken().equals(actualToken)) {
    ...
}
~~~

# CSRF 토큰 사용 예제

~~~
SingUpController.class

@Controller
@RequestMapping("/signup")
public class SingUpController {

    private final AccountService accountService;

    public SingUpController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("")
    public String signupForm(Model model) {
        model.addAttribute("account", new Account());
        return "signup";
    }

    @PostMapping("")
    public String processSingUp(@ModelAttribute Account account) {
        account.setRole("USER");
        accountService.save(account);

        return "redirect:/";
    }
}

~~~

~~~
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Signup</title>
</head>
<body>
    <!--  thymeleaf, JSP 를 사용하면 자동으로 CSRF 값을 자동으로 넣어줍니다. -->
    <form
            action="/signup"
            th:action="@{/signup}"
            th:object="${account}"
            method="post"
    >
        <p>Username: <input type="text" th:field="*{username}"></p>
        <p>Password: <input type="text" th:field="*{password}"></p>
        <p><button type="submit">SingUp</button></p>
    </form>
</body>
</html>
~~~

~~~
SecurityConfig.class

http
        .authorizeRequests()
        .mvcMatchers(
                "/signup/**"
        )
        .permitAll();
~~~

CSRF 값을 생성하여 CSRF 토큰이 전달되야 회원가입이 됩니다.

## CSRF Test Code

~~~
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SingUpControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    public void signUpForm() throws Exception {
        mockMvc
                .perform(get("/signup"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("_csrf")))
                .andDo(print());
    }

    @Test
    void processSingUp() throws Exception {
        mockMvc
                .perform(post("/signup")
                        .param(
                                "username",
                                "jjunpro"
                        )
                        .param(
                                "password",
                                "123"
                        )
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andDo(print());
    }
}
~~~

# LogoutFilter

여러 LogoutHandler를 사용하여 로그아웃시 필요한 처리를 하며 이후에는 LogoutSuccessHandler를 사용하여 로그아웃 후처리를 한다.

- LogoutHandler
    - CsrfLogoutHandler
    - SecurityContextLogoutHandler

- LogoutSuccessHandler
    - SimplUrlLogoutSuccessHandler


~~~
LogoutFilter.class

private final LogoutHandler handler;
private final LogoutSuccessHandler logoutSuccessHandler;
~~~

~~~
LogoutFilter.class

public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
        throws IOException, ServletException {
    디버그 > HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    if (requiresLogout(request, response)) {
    디버그 > Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        ...
    }
    ...
}
~~~

디버그 실행 후 로그아웃을 실행하면 requiresLogout 조건에 맞아서 실행되게 되는것을 확인할 수 있습니다.

로그아웃 이후 "/" 페이지로 이동되도록 설정해보도록 하겠습니다.

~~~
http.logout()
        .logoutUrl("/logout")
        .logoutSuccessUrl("/")
        .logoutRequestMatcher()
        .invalidateHttpSession(true)
        .deleteCookies()
        .addLogoutHandler()
        .logoutSuccessHandler();
~~~
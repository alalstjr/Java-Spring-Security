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

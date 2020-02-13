package com.example.project.controller;

import com.example.project.domain.Account;
import com.example.project.service.AccountService;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import javax.transaction.Transactional;

import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AccountService accountService;

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
    // @WithUser
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

    /**
     * =================== Form Login 테스트
     * */

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
}
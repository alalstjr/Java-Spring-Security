package com.example.project.service;

import com.example.project.context.AccountContext;
import com.example.project.domain.Account;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

    // 현재 로그인한 사용자 정보를 참조할 때
    public void dashboard() {
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();

        System.out.println("====authentication====");
        System.out.println(authentication);

        // 인증이 완료된 사용자의 정보
        Object principal = authentication.getPrincipal();

        // 사용자가 가지고 있는 권한을 나타냅니다. 권한은 ADMIN, USER ... 등등 여러개일수도 있으니 Collection
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // 인증이 완료된 사용자인지 판별합니다.
        boolean authenticated = authentication.isAuthenticated();

        // ThreadLocal을 사용하여 메소드 파라미터를 받지 않아도 유저의 정보를 가져와서 사용하였습니다.
        Account account = AccountContext.getAccount();
        System.out.println(account.getUsername());
    }

    /**
     * @Async 어노테이션을 붙이면 특정 Bean 안의 메소드를 호출할 때 별도의 Thread 를 만들어서 비동기적으로 호출을 해줍니다.
     * */
    @Async
    public void asyncService() {
        System.out.println("Async service");
    }

    @Secured("ROLE_USER")
    public void app() {
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        System.out.println("====authentication====");
        System.out.println(userDetails.getUsername());
    }
}

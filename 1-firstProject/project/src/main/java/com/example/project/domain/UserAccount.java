package com.example.project.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

public class UserAccount extends User {

    private Account account;

    public UserAccount(
            Account account
    ) {
        super(
                account.getUsername(),
                account.getPassword(),
                List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole()))
        );

        // Domain account 접근할 수 있도록 추가
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}

package com.example.project.service;

import com.example.project.domain.Account;
import com.example.project.repository.AccountRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

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

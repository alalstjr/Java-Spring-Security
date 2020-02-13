package com.example.project.context;

import com.example.project.domain.Account;

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

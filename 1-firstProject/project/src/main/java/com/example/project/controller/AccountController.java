package com.example.project.controller;

import com.example.project.domain.Account;
import com.example.project.repository.AccountRepository;
import com.example.project.service.AccountService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/account/{username}/{password}/{role}")
    public Account createAccount(
            @ModelAttribute
                    Account account
    ) {
        return accountService.save(account);
    }
}

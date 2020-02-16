package com.example.project.controller;

import com.example.project.domain.Account;
import com.example.project.service.AccountService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

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

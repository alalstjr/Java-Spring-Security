package com.example.project.controller;

import com.example.project.context.AccountContext;
import com.example.project.domain.UserAccount;
import com.example.project.repository.AccountRepository;
import com.example.project.repository.BookRepository;
import com.example.project.service.SampleService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class SampleController {

    private final SampleService     sampleService;
    private final AccountRepository accountRepository;
    private final BookRepository    bookRepository;

    public SampleController(
            SampleService sampleService,
            AccountRepository accountRepository,
            BookRepository bookRepository
    ) {
        this.sampleService = sampleService;
        this.accountRepository = accountRepository;
        this.bookRepository = bookRepository;
    }

    /**
     * 비로그인 and 로그인 사용자 둘다의 조건으로 접근제어할 경우
     */
    @GetMapping("/")
    public String index(
            Model model,
            Principal principal
    ) {
        if (principal != null) {
            model.addAttribute(
                    "message",
                    "Hello~ Index~!" + principal.getName()
            );
        }
        else {
            model.addAttribute(
                    "message",
                    "Hello~ Index~!"
            );
        }
        return "index";
    }

    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute(
                "message",
                "Hello~ info~!"
        );
        return "info";
    }

    // Login 유저만 접근이 가능한 공
    @GetMapping("/dashboard")
    public String dashboard(
            Model model,
            Principal principal
    ) {
        model.addAttribute(
                "message",
                "Hello~ dashboard~! :" + principal.getName()
        );

        // 등록된 유저의 Account 정보를 ThreadLocal 에 저장하였습니다.
        AccountContext.setAccount(accountRepository.findByUsername(principal.getName()));

        sampleService.dashboard();
        return "dashboard";
    }

    @GetMapping("/admin")
    public String admin(
            Model model,
            Principal principal
    ) {
        model.addAttribute(
                "message",
                "Hello~ admin~! :" + principal.getName()
        );
        return "admin";
    }

    // User 권한만 가진 계정만 접근 가능
    @GetMapping("/user")
    public String user(
            Model model,
            @AuthenticationPrincipal
                    UserAccount userAccount
    ) {
        model.addAttribute(
                "message",
                "Hello~ user~! :" + userAccount
                        .getAccount()
                        .getUsername()
        );

        // 현재 로그인한 유저의 책의 목록을 표시합니다.
        model.addAttribute("books", bookRepository.findCurrentUserBooks());

        return "user";
    }

    @GetMapping("/async-service")
    public String asyncService() {
        sampleService.asyncService();
        return "async-service";
    }
}

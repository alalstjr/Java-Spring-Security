package com.example.project.controller;

import com.example.project.service.SampleService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;
import java.util.jar.Attributes;

@Controller
public class SampleController {

    private final SampleService sampleService;

    public SampleController(SampleService sampleService) {
        this.sampleService = sampleService;
    }

    /**
     * 비로그인 and 로그인 사용자 둘다의 조건으로 접근제어할 경우
     */
    @GetMapping("/")
    public String index(Model model, Principal principal) {
        if (principal != null) {
            model.addAttribute(
                    "message",
                    "Hello~ Index~!" + principal.getName()
            );
        } else {
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
}

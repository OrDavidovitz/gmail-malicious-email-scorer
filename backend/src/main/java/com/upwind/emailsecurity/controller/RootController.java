package com.upwind.emailsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RootController {

    @GetMapping("/")
    public String root() {
        return "Email Risk Analyzer backend is running. Use /api/health for health checks and /api/analyze for email analysis.";
    }
}
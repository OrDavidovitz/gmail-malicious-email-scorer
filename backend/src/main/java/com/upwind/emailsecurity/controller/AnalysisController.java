package com.upwind.emailsecurity.controller;

import com.upwind.emailsecurity.config.ApiKeyProperties;
import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.EmailAnalysisResponse;
import com.upwind.emailsecurity.service.EmailAnalysisService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AnalysisController {

    private static final String API_KEY_HEADER = "X-API-Key";

    private final EmailAnalysisService emailAnalysisService;
    private final ApiKeyProperties apiKeyProperties;

    public AnalysisController(EmailAnalysisService emailAnalysisService,
                              ApiKeyProperties apiKeyProperties) {
        this.emailAnalysisService = emailAnalysisService;
        this.apiKeyProperties = apiKeyProperties;
    }

    @GetMapping("/health")
    public String health() {
        return "Email security backend is running";
    }

    @PostMapping("/analyze")
    public EmailAnalysisResponse analyze(@RequestHeader(value = API_KEY_HEADER, required = false) String apiKey,
                                         @Valid @RequestBody EmailAnalysisRequest request) {
        validateApiKey(apiKey);
        return emailAnalysisService.analyze(request);
    }

    private void validateApiKey(String apiKey) {
        if (apiKey == null || !apiKey.equals(apiKeyProperties.getKey())) {
            throw new UnauthorizedException();
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    private static class UnauthorizedException extends RuntimeException {
    }
}
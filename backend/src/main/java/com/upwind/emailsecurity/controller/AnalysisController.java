package com.upwind.emailsecurity.controller;

import com.upwind.emailsecurity.config.ApiKeyProperties;
import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.EmailAnalysisResponse;
import com.upwind.emailsecurity.service.EmailAnalysisService;
import com.upwind.emailsecurity.service.RateLimiterService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AnalysisController {

    private static final String API_KEY_HEADER = "X-API-Key";

    private final EmailAnalysisService emailAnalysisService;
    private final ApiKeyProperties apiKeyProperties;
    private final RateLimiterService rateLimiterService;

    public AnalysisController(EmailAnalysisService emailAnalysisService,
                              ApiKeyProperties apiKeyProperties,
                              RateLimiterService rateLimiterService) {
        this.emailAnalysisService = emailAnalysisService;
        this.apiKeyProperties = apiKeyProperties;
        this.rateLimiterService = rateLimiterService;
    }

    @GetMapping("/health")
    public String health() {
        return "Email security backend is running";
    }

    @PostMapping("/analyze")
    public EmailAnalysisResponse analyze(@RequestHeader(value = API_KEY_HEADER, required = false) String apiKey,
                                         @Valid @RequestBody EmailAnalysisRequest request) {
        validateApiKey(apiKey);
        validateRateLimit(apiKey);

        return emailAnalysisService.analyze(request);
    }

    private void validateApiKey(String apiKey) {
        if (apiKey == null || !apiKey.equals(apiKeyProperties.getKey())) {
            throw new UnauthorizedException();
        }
    }

    private void validateRateLimit(String apiKey) {
        if (!rateLimiterService.isAllowed(apiKey)) {
            throw new RateLimitExceededException();
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    private static class UnauthorizedException extends RuntimeException {
    }

    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    private static class RateLimitExceededException extends RuntimeException {
    }
}
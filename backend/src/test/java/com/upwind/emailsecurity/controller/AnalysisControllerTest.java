package com.upwind.emailsecurity.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AnalysisControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void analyzeWithoutApiKeyShouldReturnUnauthorized() throws Exception {
        String requestBody = """
                {
                  "from": "PayPal Security <security@paypa1-support.com>",
                  "replyTo": "support@gmail.com",
                  "subject": "Urgent: verify your account now",
                  "body": "Your account will be suspended. Click https://bit.ly/verify-paypal-now to verify your password immediately.",
                  "attachmentNames": ["invoice.pdf.exe"]
                }
                """;

        mockMvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized());
    }
    @Test
    void analyzeWithInvalidApiKeyShouldReturnUnauthorized() throws Exception {
        String requestBody = """
            {
              "from": "PayPal Security <security@paypa1-support.com>",
              "replyTo": "support@gmail.com",
              "subject": "Urgent: verify your account now",
              "body": "Your account will be suspended. Click https://bit.ly/verify-paypal-now to verify your password immediately.",
              "attachmentNames": ["invoice.pdf.exe"]
            }
            """;

        mockMvc.perform(post("/api/analyze")
                        .header("X-API-Key", "wrong-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized());
    }
    @Test
    void analyzeWithValidApiKeyShouldReturnAnalysis() throws Exception {
        String requestBody = """
                {
                  "from": "PayPal Security <security@paypa1-support.com>",
                  "replyTo": "support@gmail.com",
                  "subject": "Urgent: verify your account now",
                  "body": "Your account will be suspended. Click https://bit.ly/verify-paypal-now to verify your password immediately.",
                  "attachmentNames": ["invoice.pdf.exe"]
                }
                """;

        mockMvc.perform(post("/api/analyze")
                        .header("X-API-Key", "dev-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(100))
                .andExpect(jsonPath("$.verdict").value("CRITICAL"))
                .andExpect(jsonPath("$.signals").isArray());
    }
}
package com.upwind.emailsecurity.service;

import com.upwind.emailsecurity.model.EmailAnalysisRequest;
import com.upwind.emailsecurity.model.EmailAnalysisResponse;
import com.upwind.emailsecurity.model.Verdict;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class EmailAnalysisServiceTest {

    @Autowired
    private EmailAnalysisService emailAnalysisService;

    @Test
    void benignEmailShouldReturnLowRisk() {
        EmailAnalysisRequest request = new EmailAnalysisRequest();
        request.setFrom("Or Davidovitz <or@example.com>");
        request.setReplyTo("or@example.com");
        request.setSubject("Project meeting notes");
        request.setBody("Hi, sharing the notes from today meeting. Let me know if you have any comments.");
        request.setAttachmentNames(List.of("notes.pdf"));

        EmailAnalysisResponse response = emailAnalysisService.analyze(request);

        assertEquals(0, response.getScore());
        assertEquals(Verdict.LOW, response.getVerdict());
        assertTrue(response.getSignals().isEmpty());
    }

    @Test
    void phishingEmailShouldReturnCriticalRisk() {
        EmailAnalysisRequest request = new EmailAnalysisRequest();
        request.setFrom("PayPal Security <security@paypa1-support.com>");
        request.setReplyTo("support@gmail.com");
        request.setSubject("Urgent: verify your account now");
        request.setBody("Your account will be suspended. Click https://bit.ly/verify-paypal-now to verify your password immediately.");
        request.setAttachmentNames(List.of("invoice.pdf.exe"));

        EmailAnalysisResponse response = emailAnalysisService.analyze(request);

        assertEquals(100, response.getScore());
        assertEquals(Verdict.CRITICAL, response.getVerdict());
        assertFalse(response.getSignals().isEmpty());
    }

    @Test
    void doubleExtensionShouldNotCreateTwoAttachmentSignals() {
        EmailAnalysisRequest request = new EmailAnalysisRequest();
        request.setFrom("sender@example.com");
        request.setReplyTo("sender@example.com");
        request.setSubject("Document attached");
        request.setBody("Please review the attached document.");
        request.setAttachmentNames(List.of("invoice.pdf.exe"));

        EmailAnalysisResponse response = emailAnalysisService.analyze(request);

        long attachmentSignals = response.getSignals()
                .stream()
                .filter(signal -> signal.getCategory().equals("ATTACHMENT"))
                .count();

        assertEquals(1, attachmentSignals);
        assertEquals(30, response.getScore());
        assertEquals(Verdict.MEDIUM, response.getVerdict());
    }
}
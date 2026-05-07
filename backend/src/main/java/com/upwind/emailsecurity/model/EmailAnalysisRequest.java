package com.upwind.emailsecurity.model;

import jakarta.validation.constraints.Size;

import java.util.List;

public class EmailAnalysisRequest {

    @Size(max = 500)
    private String from;

    @Size(max = 500)
    private String replyTo;

    @Size(max = 500)
    private String subject;

    @Size(max = 20000)
    private String body;

    private List<String> attachmentNames;

    public EmailAnalysisRequest() {
    }

    public String getFrom() {
        return from;
    }

    public String getReplyTo() {
        return replyTo;
    }

    public String getSubject() {
        return subject;
    }

    public String getBody() {
        return body;
    }

    public List<String> getAttachmentNames() {
        return attachmentNames;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public void setReplyTo(String replyTo) {
        this.replyTo = replyTo;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public void setAttachmentNames(List<String> attachmentNames) {
        this.attachmentNames = attachmentNames;
    }
}
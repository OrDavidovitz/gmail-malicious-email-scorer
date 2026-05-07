package com.upwind.emailsecurity;

import com.upwind.emailsecurity.config.ApiKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ApiKeyProperties.class)
public class EmailsecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(EmailsecurityApplication.class, args);
	}
}
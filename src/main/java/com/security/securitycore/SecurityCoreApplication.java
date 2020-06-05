package com.security.securitycore;

import org.minbox.framework.api.boot.autoconfigure.swagger.annotation.EnableApiBootSwagger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
@EnableApiBootSwagger
public class SecurityCoreApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityCoreApplication.class, args);
    }

}

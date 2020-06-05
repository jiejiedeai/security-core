package com.security.securitycore.config;

import com.security.securitycore.properties.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

/**
 * 初始化工作
 */
@Component
@Order(1)
public class SystemInit implements ApplicationRunner {

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private RedisTemplate redisTemplate;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        //redis 初始化通用验证码
        redisTemplate.opsForValue().set(securityProperties.getUniversalVerificationCodeKey(),
                securityProperties.getUniversalVerificationCodeValue());
    }
}

package com.security.securitycore.security.config;

import com.security.securitycore.security.authority.DynamicSecurityInterceptor;
import com.security.securitycore.security.authority.OneVotePermit;
import com.security.securitycore.security.authority.UrlRedisSecurityMetadataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.AccessDecisionManager;

/**
 * 装配动态权限拦截器
 */
@Configuration
public class AuthorityInterceptorConfig {

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        return new OneVotePermit();
    }

    @Bean
    public DynamicSecurityInterceptor dynamicSecurityInterceptor(RedisTemplate redisTemplate) {
        return new DynamicSecurityInterceptor(urlRedisSecurityMetadataSource(redisTemplate), accessDecisionManager());
    }

    @Bean
    public UrlRedisSecurityMetadataSource urlRedisSecurityMetadataSource(RedisTemplate redisTemplate) {
        UrlRedisSecurityMetadataSource source = new UrlRedisSecurityMetadataSource(redisTemplate);
        return source;
    }
}

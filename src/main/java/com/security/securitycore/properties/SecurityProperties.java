package com.security.securitycore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * security 系统配置封装类
 */
@Component
@ConfigurationProperties(prefix = "spring.security")
@Data
public class SecurityProperties {

    /** 不登录即可访问的接口 **/
    private String [] anonymous;

    /** 登录不需要校验权限的url **/
    private String [] permits;

    /** 如果未认证过会走此接口包装了返回json结果给前端提示未认证 **/
    private String loginPage="/auth/require";

    /** 用户名密码登录接口 UsernamePasswordAuthenticationFilter默认登录接口是/login**/
    private String loginProcessingUrl="/auth/signIn";

    /** 退出接口地址 **/
    private String logoutUrl = "/auth/signOut";

    /** 放行的静态资源 **/
    private String [] statics ={"/swagger-ui.html",
            "/swagger/**",
            "/webjars/**",
            "/swagger-resources/**",
            "/v2/**"};

    /** 图片验证码长度 **/
    private int imageCodeLength;

    /** 图片验证码过期时间 **/
    private long imageExpireIn;

    /** 短信验证码长度 **/
    private int smsCodeLength;

    /** 短信验证码过期时间 **/
    private long smsExpireIn;

    /** 图片rediss的essionKey **/
    private String sessionKeyImageCode = "SESSION_KEY_IMAGE_CODE";

    /** 短信redis的sessionkey **/
    private String sessionKeySmsCode = "SESSION_KEY_SMS_CODE";

    /** 通用验证码key **/
    private String universalVerificationCodeKey = "UNIVERSAL_VERIFICATION_CODE";

    /** 记住我参数名称 **/
    private String remeberMeParameterName = "remeberMe";

    /** 通用验证码值 **/
    private String universalVerificationCodeValue;

    /** 拦截需要图形验证的url **/
    private String [] validateImageUrls;

    /** 拦截需要短信验证的url **/
    private String [] validateSmsUrls;

    /** security 记住我时长 **/
    private int tokenValiditySeconds;

    /** url在redis中不存在 是否校验权限开关**/
    private boolean noMatcherPermit = false;
}

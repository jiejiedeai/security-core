package com.security.securitycore.security.config;

import com.security.securitycore.security.MobileUserDetailServiceImpl;
import com.security.securitycore.security.filter.sms.MobileAuthenticationFilter;
import com.security.securitycore.security.handler.CustomerAuthenticationFailureHandler;
import com.security.securitycore.security.handler.CustomerAuthenticationSuccessHandler;
import com.security.securitycore.security.provider.MobileAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Component;

/**
 * 用于组合其他关于手机登录的组件
 */
@Component
public class MobileAuthenticationConfig
        extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Autowired
    private CustomerAuthenticationSuccessHandler customerAuthenticationSuccessHandler;

    @Autowired
    private CustomerAuthenticationFailureHandler customerAuthenticationFailureHandler;


    @Override
    public void configure(HttpSecurity http) throws Exception {
        MobileAuthenticationFilter mobileAuthenticationFilter = new MobileAuthenticationFilter();
        //获取容器中已经存在的AuthentionManager对象，并传入mobileAuthenticationFilter里面
        mobileAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

        //指定记住我功能
        mobileAuthenticationFilter.setRememberMeServices(http.getSharedObject(RememberMeServices.class));

        //获取当前共享池中的session登录验证策略 解决用户名密码登录后同一个用户使用手机号登录踢下线
        mobileAuthenticationFilter.setSessionAuthenticationStrategy(http.getSharedObject(SessionAuthenticationStrategy.class));

        //失败和成功处理器
        mobileAuthenticationFilter.setAuthenticationSuccessHandler(customerAuthenticationSuccessHandler);
        mobileAuthenticationFilter.setAuthenticationFailureHandler(customerAuthenticationFailureHandler);

        //构建第一个MobileAuthenticationProvider实例,接收和查询mobileAuthenticationService通过手机号查询用户信息
        MobileAuthenticationProvider mobileAuthenticationProvider = new MobileAuthenticationProvider();
        mobileAuthenticationProvider.setUserDetailsService(new MobileUserDetailServiceImpl());
        //将provider 绑定到HttpSecurity上，并将手机号认证过滤器绑定到用户名密码过滤器之后
        http
                .authenticationProvider(mobileAuthenticationProvider)
                .addFilterAfter(mobileAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    }
}

package com.security.securitycore.security.handler;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义登录成功方法
 */
@Component
@Slf4j
public class CustomerAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {


    /**
     * @param request
     * @param response
     * @param authentication Authentication 也是security 的一个核心接口 作用是封装我们的用户信息
     *                       认证信息包括 请求id、session是什么、认证通过后自定义的UserDetails等
     * @throws IOException
     * @throws ServletException
     */
    @SneakyThrows
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("登录成功");
    }
}


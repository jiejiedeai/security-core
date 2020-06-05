package com.security.securitycore.security.session;

import com.security.securitycore.security.handler.CustomerAuthenticationFailureHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * 当同一个用户的session达到指定数量后 会执行该类的方法
 */
@Component
@Slf4j
public class CustomerSessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {

    @Autowired
    private CustomerAuthenticationFailureHandler customerAuthenticationFailureHandler;

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        //重定向到登录页面 因为前后端分离此处指显示谁被踢下线了
        UserDetails userDetails = (UserDetails) event.getSessionInformation().getPrincipal();
        AuthenticationException exception =
                new AuthenticationServiceException(String.format("{%s}用户在另一台电脑登录，您被踢下线",userDetails.getUsername()));
        customerAuthenticationFailureHandler.onAuthenticationFailure(event.getRequest(),
                event.getResponse(),exception);

    }
}

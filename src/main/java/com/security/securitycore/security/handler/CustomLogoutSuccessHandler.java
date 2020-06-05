package com.security.securitycore.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.securitycore.model.JsonResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Slf4j
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SessionRegistry sessionRegistry;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication != null) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String username = userDetails.getUsername();
            log.info(username + "退出成功");
        }
        log.error("authentication为null");
        //退出清除sessionid 或者采用在securityConfig中 退出后直接调用deleteCookies
        sessionRegistry.removeSessionInformation(request.getSession().getId());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(JsonResult.success("退出成功")));
    }
}

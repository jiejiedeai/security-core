package com.security.securitycore.security.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.securitycore.model.JsonResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * session过期策略
 */
@Component
@Slf4j
public class CustomerInvalidSessionStrategy implements InvalidSessionStrategy {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SessionRegistry sessionRegistry;

    @Override
    public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        sessionRegistry.removeSessionInformation(request.getSession().getId());
        response.getWriter().write(objectMapper.writeValueAsString(JsonResult.error("session失效")));
    }

}

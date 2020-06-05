package com.security.securitycore.security.filter.sms;

import com.security.securitycore.exception.ValidateCodeException;
import com.security.securitycore.properties.SecurityProperties;
import com.security.securitycore.security.handler.CustomerAuthenticationFailureHandler;
import lombok.Data;
import lombok.experimental.Accessors;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 自定义短信验证码过滤器
 */
@Data
@Accessors(chain = true)
@Component
public class ValidateSmsCodeFilter extends OncePerRequestFilter implements InitializingBean {

    @Autowired
    private RedisTemplate redisTemplate;

    @Autowired
    private SecurityProperties securityProperties;

    //失败异常处理器
    @Autowired
    private CustomerAuthenticationFailureHandler authenticationFailureHandler;

    //需要校验的url
    private List<String> urls = new ArrayList<>();

    //spring 工具类 它主要用来做类urls字符串匹配
    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        //将配置文件中需要使用验证码校验的url添加到set中
        urls.addAll(Arrays.asList(securityProperties.getValidateSmsUrls()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        AtomicBoolean flag = new AtomicBoolean(false);
        urls.stream()
                .filter(url -> antPathMatcher.match(url,request.getRequestURI()))
                .forEach(url -> {
                    flag.set(true);
                });
        if(flag.get()){
            try{
                validate(new ServletWebRequest(request));
            }catch (ValidateCodeException e){
                //捕获到异常用自定义失败处理
                authenticationFailureHandler.onAuthenticationFailure(request,response,e);
                return;
            }
        }
        //如果不是获取验证码的请求或者验证成功则直接调用后边的过滤器
        filterChain.doFilter(request,response);
    }

    /**
     * 校验验证码逻辑
     * @param request
     */
    private void validate(ServletWebRequest request) throws ValidateCodeException, ServletRequestBindingException {
        String codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(),"smsCode");
        if(!StringUtils.isNotBlank(codeInRequest)){
            throw new ValidateCodeException("验证码的值不能为空");
        }
        String sessionId = request.getSessionId();
        String universalVerificationCode = (String) redisTemplate.opsForValue().get(securityProperties.getUniversalVerificationCodeKey());
        String sessionKeySmsCode = securityProperties.getSessionKeySmsCode();
        if(!codeInRequest.equals(universalVerificationCode)){
            String smsCode = (String) redisTemplate.opsForValue().get(sessionId+sessionKeySmsCode);
            Optional<String> smsCodeOptional =Optional.ofNullable(smsCode);
            smsCodeOptional.orElseThrow(() -> new ValidateCodeException("验证码不存在"));
            if(!StringUtils.equals(smsCode,codeInRequest)){
                throw new ValidateCodeException("验证码不匹配");
            }
            redisTemplate.delete(sessionId+sessionKeySmsCode);
        }
    }
}

package com.security.securitycore.security.filter.sms;

import com.security.securitycore.properties.Constant;
import com.security.securitycore.security.token.MobileAuthenticationToken;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 用于校验用户手机号是否通过验证
 */
public class MobileAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String MOBILE = "mobile";

    //携带请求中参数名字
    private String mobileParameter = MOBILE;

    //当前过滤器是否只处理post请求
    private boolean postOnly = true;

    public MobileAuthenticationFilter() {
        //对应表单中请求手机号登录接口
        super(new AntPathRequestMatcher(Constant.LOGIN_MOBILEIN, "POST"));
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("请求认证方法不支持: " + request.getMethod());
        }

        String mobile = obtainMobile(request);
        if (mobile == null) {
            mobile = "";
        }
        MobileAuthenticationToken authRequest = new MobileAuthenticationToken(mobile);
        setDetails(request, authRequest);
        //通过AuthentictionToken调用AuthenticationManager 然后会指定我们自定义的SmsCodeAuthenticationProvider
        return this.getAuthenticationManager().authenticate(authRequest);
    }


    /**
     * 从request中获取手机号
     * @param request
     * @return
     */
    @Nullable
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    /**
     * 将请求的详情ip、sessionid 设置到认证详情中去
     * @param request
     * @param authRequest
     */
    protected void setDetails(HttpServletRequest request, MobileAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    public void setMobileParameter(String mobileParameter) {
        Assert.hasText(mobileParameter, "mobile parameter must not be empty or null");
        this.mobileParameter = mobileParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getMobileParameter() {
        return mobileParameter;
    }

}

package com.security.securitycore.security.authority;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

import javax.servlet.*;
import java.io.IOException;

/**
 * 动态权限过滤器
 */
public class DynamicSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {

    private boolean observeOncePerRequest = false;
    /**
     * 该字段将作为Key保存到请求中，如果对应的值为True表明当前Url已被别的过滤器处理过
     */
    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

    /**
     * 装配自定义的FilterInvocationSecurityMetadataSource，用于加载Url及其对应的权限信息
     */
    private final FilterInvocationSecurityMetadataSource securityMetadataSource;
    /**
     * 注入自定义的访问决策管理器（AccessDecisionManager），用于判断当前用户是否有权访问当前Url
     */
    private final AccessDecisionManager accessDecisionManager;

    public DynamicSecurityInterceptor(FilterInvocationSecurityMetadataSource securityMetadataSource, AccessDecisionManager accessDecisionManager) {
        this.securityMetadataSource = securityMetadataSource;
        this.accessDecisionManager = accessDecisionManager;
        super.setAccessDecisionManager(this.accessDecisionManager);
    }

    @Override
    public Class<?> getSecureObjectClass() {
        return FilterInvocation.class;
    }

    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        /**
         * FilterInvocation 封装了请求信息和响应信息以及过滤链对象
         */
        FilterInvocation fi = new FilterInvocation(servletRequest, servletResponse, filterChain);
        invoke(fi);
    }

    @Override
    public void destroy() {

    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if ((fi.getRequest() != null)
                && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
                && observeOncePerRequest) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null && observeOncePerRequest) {
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }
            /**
             * 执行权限校验逻辑
             */
            InterceptorStatusToken token = super.beforeInvocation(fi);
            /**
             * 执行完毕交给下个过滤O`器进行处理
             */
            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }
            super.afterInvocation(token, null);
        }
    }

    public boolean isObserveOncePerRequest() {
        return observeOncePerRequest;
    }

    public void setObserveOncePerRequest(boolean observeOncePerRequest) {
        this.observeOncePerRequest = observeOncePerRequest;
    }
}

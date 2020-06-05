package com.security.securitycore.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.util.Collection;

/**
 * 封装验证码登录信息
 * 身份认证之前封装的是手机号
 * 身份认证成功之后封装的是用户信息
 */
public class MobileAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    //principal是认证信息 认证前世手机号 认证后放用户信息
    private final Object principal;

    /**
     * 认证之前使用的构造方法 此方法会标识未认证
     * @param mobile
     */
    public MobileAuthenticationToken(String mobile) {
        super(null);
        this.principal = mobile;
        setAuthenticated(false);
    }

    /**
     * 认证通过后会重新创建实例 会重新封装认证信息
     * principal 用户信息
     * authorities 权限信息
     * @param principal
     * @param authorities
     */
    public MobileAuthenticationToken(Object principal , Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true); // must use super, as we override
    }

    /**
     * 手机号登录没有密码 父类中的抽象方法必须要实现 此处直接返回null
     * @return
     */
    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
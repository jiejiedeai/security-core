package com.security.securitycore.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * AuthenticationException security 自定义验证码的抽象异常 在身份认证中异常的一个基类
 */
public class ValidateCodeException extends AuthenticationException {

    private static final long serialVersionUID = -87561947790721791L;

    public ValidateCodeException(String msg) {
        super(msg);
    }
}

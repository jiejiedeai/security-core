package com.security.securitycore.security.provider;

import com.security.securitycore.security.token.MobileAuthenticationToken;
import lombok.Data;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Optional;

/**
 * 手机认证处理提供者
 */
@Data
public class MobileAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    /**
     * 认证处理
     * 通过手机号码查询认证信息 通过MobileUserDetailServiceImpl实现
     * 通过手机号查询到认证信息 则认为认证通过 封装到Authentication对象中
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MobileAuthenticationToken mobileAuthenticationToken = (MobileAuthenticationToken)authentication;
        String mobile = (String) mobileAuthenticationToken.getPrincipal();
        Optional<UserDetails> userDetailsOptional = Optional.ofNullable(userDetailsService.loadUserByUsername(mobile));
        userDetailsOptional.orElseThrow(() -> new AuthenticationServiceException("手机号未注册"));
        UserDetails userDetails = userDetailsOptional.get();
        //认证通过
        MobileAuthenticationToken authenticationToken = new MobileAuthenticationToken(userDetails, userDetails.getAuthorities());
        //设置details 从传入的token中获取详细信息 session信息等封装到认证通过后的token中
        authenticationToken.setDetails(mobileAuthenticationToken.getDetails());
        return authenticationToken;
    }

    /**
     * 通过此方法来选择对应的Provider
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return MobileAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

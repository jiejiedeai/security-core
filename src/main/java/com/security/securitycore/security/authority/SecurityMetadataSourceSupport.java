package com.security.securitycore.security.authority;

import java.util.List;

public interface SecurityMetadataSourceSupport {

    /**
     * 获取所有的URL以及对应的权限信息,用于持久化到Redis
     * @return
     */
    List<UserAuthority> getAllAuthority();
}

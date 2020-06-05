package com.security.securitycore.security.authority;

import java.util.Collections;
import java.util.List;

public class DefaultSecurityMetadataSourceSupport implements SecurityMetadataSourceSupport {
    @Override
    public List<UserAuthority> getAllAuthority() {
        return Collections.emptyList();
    }
}

package com.security.securitycore.security.authority;

import lombok.Data;

import java.util.List;

/**
 * 用户资源列表
 */
@Data
public class UserAuthority {

    /** 资源路径 */
    private String uri;

    /** 角色列表 角色id*/
    private List<Integer> authorities;

}
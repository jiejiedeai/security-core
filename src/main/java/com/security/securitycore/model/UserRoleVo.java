package com.security.securitycore.model;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.io.Serializable;
import java.util.List;

@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
public class UserRoleVo implements Serializable {

    private static final long serialVersionUID = 8874249846093757904L;

    private String username;

    private String password;

    private Boolean locked;

    private List<Role> roles;

}

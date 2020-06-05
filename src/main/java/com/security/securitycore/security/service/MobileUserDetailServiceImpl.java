package com.security.securitycore.security;

import com.security.securitycore.mapper.UserMapper;
import com.security.securitycore.model.Role;
import com.security.securitycore.model.UserRoleVo;
import com.security.securitycore.util.BeanUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 通过手机号获取用户信息和资源
 */
public class MobileUserDetailServiceImpl implements UserDetailsService {

    private UserMapper userMapper= BeanUtil.getBean(UserMapper.class);

    @Override
    public UserDetails loadUserByUsername(String mobile) throws UsernameNotFoundException {
        Optional<UserRoleVo> optional = Optional.ofNullable(userMapper.searchUserByMobile(mobile));
        optional.orElseThrow(() -> new UsernameNotFoundException("用户不存在"));
        UserRoleVo userRole = optional.get();
        List<Role> roles = userRole.getRoles();
        Collection<GrantedAuthority> authorities = getAuthorities(roles);
        //需要3个参数 用户名，密码，权限 其余4个校验超时、冻结、过期等默认为true
        User user =
                new User(userRole.getUsername(),
                        userRole.getPassword(),
                        authorities);
        return user;
    }

    /**
     * 将用户角色转换成Security需要的
     * @param roles
     * @return
     */
    private Collection<GrantedAuthority> getAuthorities(List<Role> roles){
        if(!CollectionUtils.isEmpty(roles)){
            String [] roleNames = roles.stream().map(role -> role.getId().toString()).collect(Collectors.toList()).toArray(new String[roles.size()]);
            return AuthorityUtils.createAuthorityList(roleNames);
        }else{
            return AuthorityUtils.createAuthorityList();
        }
    }
}

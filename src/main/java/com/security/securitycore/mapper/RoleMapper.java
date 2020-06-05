package com.security.securitycore.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.security.securitycore.model.Role;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * <p>
 * 角色表 Mapper 接口
 * </p>
 *
 * @author qp
 * @since 2020-01-23
 */
public interface RoleMapper extends BaseMapper<Role> {

    /**
     * 查询用户id查询角色列表
     * @param userId
     * @return
     */
    List<Role> searchUserRoles(
            @Param("userId") Integer userId);
}

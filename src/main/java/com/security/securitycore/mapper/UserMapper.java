package com.security.securitycore.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.security.securitycore.model.User;
import com.security.securitycore.model.UserRoleVo;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * <p>
 * 用户表 Mapper 接口
 * </p>
 *
 * @author qp
 * @since 2020-03-21
 */
public interface UserMapper extends BaseMapper<User> {

    /**
     * UserDetailService 根据用户名查询用户
     * @param username
     * @return
     */
    UserRoleVo searchUserIsExists(
            @Param("username") String username);

    /**
     * 根据手机号查询用户
     * @param mobile
     * @return
     */
    UserRoleVo searchUserByMobile(
            @Param("mobile") String mobile);

    /**
     * 查询用户列表
     * @param page
     * @param name
     * @return
     */
    IPage<User> searchUserList(Page<User> page,@Param("name")String name);
}

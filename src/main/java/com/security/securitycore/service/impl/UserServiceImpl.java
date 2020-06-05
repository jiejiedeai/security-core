package com.security.securitycore.service.impl;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.security.securitycore.mapper.UserMapper;
import com.security.securitycore.model.JsonResult;
import com.security.securitycore.model.User;
import com.security.securitycore.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service("userServiceImpl")
public class UserServiceImpl extends ServiceImpl<UserMapper,User> implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public JsonResult<IPage<User>> searchUserList(Integer currtentPage, Integer size,String name) {
        Page<User> page = new Page<>();
        page.setCurrent(currtentPage).setSize(size);
        IPage<User> userIPage = userMapper.searchUserList(page,name);
        return JsonResult.success(userIPage);
    }
}

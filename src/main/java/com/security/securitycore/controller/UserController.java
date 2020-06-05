package com.security.securitycore.controller;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.security.securitycore.model.JsonResult;
import com.security.securitycore.model.Role;
import com.security.securitycore.model.User;
import com.security.securitycore.service.UserService;
import com.security.securitycore.service.ValidateCodeService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.constraints.NotNull;

@RestController
@RequestMapping("/user/")
@Api(tags = "用户模块")
public class UserController {

    @Autowired
    private UserService userService;

    @ApiOperation(value = "查询用户列表", notes = "查询用户列表")
    @PostMapping("searchUserList")
    public JsonResult<IPage<User>> searchUserList(
            @ApiParam(value = "当前页", name = "currtentPage", required = true,example = "1")
            @RequestParam(value = "currtentPage", required = true)
                    Integer currtentPage,
            @ApiParam(value = "每页条数", name = "size", required = true,example = "10")
            @RequestParam(value = "size", required = true)
                    Integer size,
            @ApiParam(value = "名称", name = "name", required = false)
            @RequestParam(value = "name", required = false)
                    String name
    ){
        return userService.searchUserList(currtentPage,size,name);
    }
}

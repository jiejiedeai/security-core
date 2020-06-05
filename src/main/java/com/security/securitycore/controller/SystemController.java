package com.security.securitycore.controller;

import com.security.securitycore.exception.CustomerException;
import com.security.securitycore.model.JsonResult;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import java.io.IOException;

@RestController
@Slf4j
@Api(tags = "登录认证")
@RequestMapping("/auth/")
public class SystemController {

    @PostMapping("mobileIn")
    @ApiOperation(value = "手机验证码登录", notes = "手机验证码登录")
    public void mobileIn(
            @ApiParam(value = "手机号", name = "mobile", required = true)
            @RequestParam(value = "mobile", required = true)
            @NotBlank(message = "手机号不能为空")
            @Pattern(regexp = "^((13[0-9])|(14[5|7])|(15([0-3]|[5-9]))|(17[013678])|(18[0-9]))\\d{8}$",
                    message = "手机号格式不正确")
                    String mobile,
            @ApiParam(value = "短信验证码", name = "smsCode", required = true)
            @RequestParam(value = "smsCode", required = true)
            @NotBlank(message = "短信验证码不能为空")
                    String smsCode,

            @ApiParam(value = "记住我 0.不勾选 1.勾选", name = "remeberMe", required = false,example = "1")
            @RequestParam(value = "remeberMe", required = false)
                    Integer remeberMe
    ) {
        log.info("调用security登录过滤器");
    }


    @PostMapping("signIn")
    @ApiOperation(value = "用户名密码登录", notes = "用户名密码登录")
    public void signIn(
            @ApiParam(value = "用户名", name = "username", required = true)
            @RequestParam(value = "username", required = true)
            @NotBlank(message = "用户名不能为空")
                    String username,
            @ApiParam(value = "密码", name = "password", required = true)
            @RequestParam(value = "password", required = true)
            @NotBlank(message = "密码不能为空")
                    String password,
            @ApiParam(value = "图形验证码", name = "imageCode", required = false)
            @RequestParam(value = "imageCode", required = false)
                    String imageCode,
            @ApiParam(value = "记住我 0.不勾选 1.勾选", name = "remeberMe", required = false,example = "1")
            @RequestParam(value = "remeberMe", required = false)
                    Integer remeberMe
    ) {
        log.info("调用security登录过滤器");
    }

    @ApiOperation(value = "当需要身份认真时候跳转到这里", notes = "如果有异常状态码是401")
    @GetMapping("require")
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    public JsonResult<String> require(HttpServletRequest request, HttpServletResponse response) throws IOException, CustomerException {
        String targetUrl = request.getRequestURI();
        log.info("引发跳转的请求是:"+targetUrl);
        return JsonResult.error("需要身份认证通过");
    }

    @ApiOperation(value = "获取用户登录信息", notes = "获取用户登录信息")
    @PostMapping("getAuthentication")
    public JsonResult<Authentication> getAuthenticationByWeb() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return JsonResult.success(authentication);
    }

    @PostMapping("signOut")
    @ApiOperation(value = "退出", notes = "退出")
    public void signOut() {
        log.info("调用security退出过滤器");
    }

}

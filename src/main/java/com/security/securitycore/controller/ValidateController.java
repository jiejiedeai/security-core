package com.security.securitycore.controller;

import com.security.securitycore.model.JsonResult;
import com.security.securitycore.properties.SecurityProperties;
import com.security.securitycore.service.ValidateCodeService;
import com.security.securitycore.util.ImageCode;
import com.security.securitycore.util.SmsCode;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/validate/")
@Api(tags = "验证码")
@Slf4j
public class ValidateController {

    @Autowired
    private ValidateCodeService validateCodeService;

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private RedisTemplate redisTemplate;


    @ApiOperation(value = "获取图形验证码", notes = "获取图形验证码")
    @PostMapping("codeImage")
    public JsonResult<String> codeImage(
            HttpServletRequest request, HttpServletResponse response) throws IOException {
        ImageCode imageCode = validateCodeService.createImageCode(new ServletWebRequest(request));
        String sessionId = request.getSession().getId();
        long expireIn = securityProperties.getImageExpireIn();
        String sessionKeyImageCode = securityProperties.getSessionKeyImageCode();
        //将随机数保存到redis中
        redisTemplate.opsForValue().set(sessionId + sessionKeyImageCode, imageCode.getCode(), expireIn, TimeUnit.SECONDS);
        //将生成的图片写到response中
//        ImageIO.write(imageCode.getBufferedImage(), "JPEG", response.getOutputStream());
        log.info("图形的验证码是:{}",imageCode.getCode());
        return JsonResult.success("图形的验证码是:"+imageCode.getCode());
    }

    @ApiOperation(value = "获取短信验证码", notes = "获取短信验证码")
    @PostMapping("codeSms")
    public JsonResult<String> codeSms(
            @ApiParam(value = "手机号", name = "mobile", required = true)
            @RequestParam(value = "mobile", required = true)
            @NotBlank(message = "手机号不能为空")
            @Pattern(regexp = "^((13[0-9])|(14[5|7])|(15([0-3]|[5-9]))|(17[013678])|(18[0-9]))\\d{8}$",
                    message = "手机号格式不正确")
                    String mobile,
            HttpServletRequest request, HttpServletResponse response) throws IOException, ServletRequestBindingException {
        SmsCode smsCode = validateCodeService.createSmsCode(new ServletWebRequest(request));
        String sessionId = request.getSession().getId();

        long expireIn = securityProperties.getSmsExpireIn();
        String sessionKeySmsCode = securityProperties.getSessionKeySmsCode();
        //将随机数保存到redis中
        redisTemplate.opsForValue().set(sessionId + sessionKeySmsCode, smsCode.getCode(), expireIn, TimeUnit.SECONDS);
        //通过短信服务商将短信发送出去 此处测试返回给json
        log.info("手机号:{}的短信验证码是:{}",mobile,smsCode.getCode());
        return JsonResult.success("手机号:"+mobile+"的短信验证码是:"+smsCode.getCode());
    }

}

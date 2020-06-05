package com.security.securitycore.service;

import com.security.securitycore.util.ImageCode;
import com.security.securitycore.util.SmsCode;
import org.springframework.web.context.request.ServletWebRequest;

import java.awt.*;

public interface ValidateCodeService {

    //生成图片验证码
    ImageCode createImageCode(ServletWebRequest request);

    //获取颜色
    Color getRandColor(int fc, int bc);

    //生成短信验证码
    SmsCode createSmsCode(ServletWebRequest request);

}

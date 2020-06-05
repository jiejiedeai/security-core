package com.security.securitycore.util;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class SmsCode implements Serializable {

    private static final long serialVersionUID = -2585145770382363335L;

    //随机数 放到session 后边用户登录验证
    private String code;

    //验证码过期时间
    private LocalDateTime expireTime;

    //生成一个多少秒过期的构造函数
    public SmsCode(String code, long expireIn) {
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireIn);
    }

    /**
     * 判断验证码时间是否过期
     *
     * @return
     */
    public boolean isExpried() {
        return LocalDateTime.now().isAfter(expireTime);
    }
}

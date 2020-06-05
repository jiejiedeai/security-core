package com.security.securitycore.util;

import lombok.*;
import lombok.experimental.Accessors;

import java.awt.image.BufferedImage;
import java.io.Serializable;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@AllArgsConstructor
@NoArgsConstructor
public class ImageCode extends SmsCode implements Serializable {

    private static final long serialVersionUID = -2546027435600975996L;

    //验证码过期时间
    private BufferedImage bufferedImage;

    //生成一个多少秒过期的构造函数
    public ImageCode(BufferedImage bufferedImage, String code, long expireIn) {
        super(code, expireIn);
        this.bufferedImage = bufferedImage;
    }

}

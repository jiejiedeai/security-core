package com.security.securitycore.service.impl;

import com.security.securitycore.properties.SecurityProperties;
import com.security.securitycore.service.ValidateCodeService;
import com.security.securitycore.util.ImageCode;
import com.security.securitycore.util.SmsCode;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.Random;
import java.util.stream.IntStream;

@Service
public class ValidateCodeServiceImpl implements ValidateCodeService {

    @Autowired
    private SecurityProperties securityProperties;

    /**
     * 生成随机数图片
     *
     * @param request
     * @return
     */
    @Override
    public ImageCode createImageCode(ServletWebRequest request) {
        int width = ServletRequestUtils.getIntParameter(request.getRequest(), "width", 67);
        int height = ServletRequestUtils.getIntParameter(request.getRequest(), "height", 23);
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics g = image.createGraphics();
        Random random = new Random(System.currentTimeMillis());
        g.setColor(getRandColor(200, 250));
        g.fillRect(0, 0, width, height);
        g.setFont(new Font("Times New Roman", Font.ITALIC, 20));
        g.setColor(getRandColor(160, 200));
        IntStream.range(0, 155).forEach(data -> {
            int x = random.nextInt(width);
            int y = random.nextInt(height);
            int xl = random.nextInt(12);
            int yl = random.nextInt(12);
            g.drawLine(x, y, x + xl, y + yl);
        });
        StringBuffer sRand = new StringBuffer("");
        //生成随机数
        IntStream
                .range(0, securityProperties.getImageCodeLength())
                .forEach(data -> {
                    String rand = String.valueOf(random.nextInt(10));
                    sRand.append(rand);
                    g.setColor(new Color(20 + random.nextInt(110), 20 + random.nextInt(110), 20 + random.nextInt(110)));
                    g.drawString(rand, 13 * data + 6, 16);
                });
        g.dispose();
        return new ImageCode(image, sRand.toString(), securityProperties.getImageExpireIn());
    }

    /**
     * 获取颜色
     *
     * @param fc
     * @param bc
     * @return
     */
    @Override
    public Color getRandColor(int fc, int bc) {
        Random random = new Random(System.currentTimeMillis());
        if (fc > 255) {
            fc = 255;
        }
        if (bc > 255) {
            bc = 255;
        }
        int r = fc + random.nextInt(bc - fc);
        int g = fc + random.nextInt(bc - fc);
        int b = fc + random.nextInt(bc - fc);
        return new Color(r, g, b);
    }

    @Override
    public SmsCode createSmsCode(ServletWebRequest request) {
        String code = RandomStringUtils.randomNumeric(securityProperties.getSmsCodeLength());

        return new SmsCode(code, securityProperties.getSmsExpireIn());
    }

}

package com.security.securitycore.config;

import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alibaba.fastjson.support.config.FastJsonConfig;
import com.alibaba.fastjson.support.spring.FastJsonHttpMessageConverter;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.util.List;

@Configuration
public class JsonConvertConfig implements WebMvcConfigurer {

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        /*
         * 1、需要先定义一个convert转换消息的对象 2、添加fastJson的配置信息，比如：是否要格式化返回json数据 3、在convert中添加配置信息
         * 4、将convert添加到converters当中
         *
         */
        // 1、需要先定义一个·convert转换消息的对象；
        FastJsonHttpMessageConverter fastConverter = new FastJsonHttpMessageConverter();
        // 2、添加fastjson的配置信息，比如 是否要格式化返回json数据
        FastJsonConfig fastJsonConfig = new FastJsonConfig();
        fastJsonConfig.setSerializerFeatures(SerializerFeature.PrettyFormat);
        //修改配置返回内容的过滤
        fastJsonConfig.setSerializerFeatures(
            //消除对同一对象循环引用的问题，默认为false（如果不配置有可能会进入死循环）
            SerializerFeature.DisableCircularReferenceDetect,
            //字符类型字段如果为null,输出为"",而非null
            SerializerFeature.WriteNullStringAsEmpty,
            //List字段如果为null,输出为[],而非null
            SerializerFeature.WriteNullListAsEmpty,
            //Boolean字段如果为null,输出为false,而非null
            SerializerFeature.WriteNullBooleanAsFalse,
            //是否输出值为null的字段,默认为false。
            SerializerFeature.WriteMapNullValue
        );
        // 3、在convert中添加配置信息.
        fastConverter.setFastJsonConfig(fastJsonConfig);
        // 4、将convert添加到converters当中.
        converters.add(fastConverter);
    }
}

package com.security.securitycore.model;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class JsonResult<T> implements Serializable {


    private static final Integer SUCCESS_CODE = 200;

    private static final String SUCCESS_MSG = "OK";

    private static final Integer ERROR_CODE = 400;

    private static final long serialVersionUID = 3722999012210320237L;

    @ApiModelProperty(value = "返回数据")
    private T data;

    @ApiModelProperty(value = "错误信息")
    private String msg = "";

    @ApiModelProperty(value = "状态 200成功 400失败 ")
    private Integer code = 200;

    public static <T> JsonResult<T> success(T data) {
        JsonResult<T> result = new JsonResult<>();
        return result
                .setCode(SUCCESS_CODE)
                .setMsg(SUCCESS_MSG)
                .setData(data);

    }

    public static <T> JsonResult<T> error(String message) {
        JsonResult<T> result = new JsonResult<>();
        return result
                .setCode(ERROR_CODE)
                .setMsg(message);
    }

    public static Integer getErrorCode(){
        return ERROR_CODE;
    }
}

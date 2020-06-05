package com.security.securitycore.model;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.security.securitycore.validate.AddValidate;
import com.security.securitycore.validate.UpdateValidate;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@ApiModel(value="Test", description="Test")
public class Test {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键")
    @NotNull(message="年龄不能为空")
    private Integer age;

    @ApiModelProperty(value = "用户名")
    @NotBlank(message="名称不能为空")
    private String username;
}

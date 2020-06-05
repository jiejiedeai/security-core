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
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * <p>
 * 用户表
 * </p>
 *
 * @author qp
 * @since 2020-03-21
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@ApiModel(value="User对象", description="用户表")
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键")
    @TableId(value = "id", type = IdType.AUTO)
    @NotNull(message="用户不能为空",groups = {UpdateValidate.class})
    private Integer id;

    @ApiModelProperty(value = "用户名")
    @NotBlank(message="用户不能为空",groups = {AddValidate.class})
    private String username;

    @ApiModelProperty(value = "密码")
    private String password;

    @ApiModelProperty(value = "姓名")
    @NotBlank(message="姓名不能为空",groups = {AddValidate.class})
    private String name;

    @ApiModelProperty(value = "创建时间")
    private LocalDateTime createTime;

    @ApiModelProperty(value = "修改时间")
    private LocalDateTime updateTime;

    @ApiModelProperty(value = "手机号")
    @NotBlank(message = "手机号不能为空", groups = {AddValidate.class, UpdateValidate.class})
    @Pattern(regexp = "^((13[0-9])|(14[0-9]])|(15([0-9]))|(16([0-9]))|(17[0-9])|(18[0-9])|(19[0-9]))\\d{8}$",  message = "手机号格式不正确", groups = {AddValidate.class})
    private String mobile;

    @ApiModelProperty(value = "状态 0.删除 1.正常")
    private Integer status;

    @ApiModelProperty(value = "是否冻结 false:未冻结 true.冻结")
    private Boolean locked;

    @ApiModelProperty(value = "用户类型  1.系统管理员  2.物业  3.商户")
    @NotNull(message = "用户类型不能为空",groups = AddValidate.class)
    @Range(min=1,max = 3,message = "用户类型不合法",groups = AddValidate.class)
    private Integer type;


}

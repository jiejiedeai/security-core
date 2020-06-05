package com.security.securitycore.model;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.security.securitycore.validate.AddValidate;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * <p>
 * 资源
 * </p>
 *
 * @author qp
 * @since 2020-03-21
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@ApiModel(value="Resource对象", description="资源")
public class Resource implements Serializable {

    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键")
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    @ApiModelProperty(value = "上级菜单")
    @NotNull(message = "上级菜单不能为空 如果是顶级菜单默认是0",groups = AddValidate.class)
    private Integer parentId;

    @ApiModelProperty(value = "资源名称")
    @NotBlank(message = "资源名称不能为空",groups = AddValidate.class)
    private String resourceName;

    @ApiModelProperty(value = "资源路径")
    private String resourceUrl;

    @ApiModelProperty(value = "资源类型 1..模块 2.功能 3.按钮")
    @NotNull(message = "资源类型不能为空",groups = AddValidate.class)
    @Range(min = 1,max = 3,message = "资源类型不合法",groups = AddValidate.class)
    private Integer resourceType;

    @ApiModelProperty(value = "创建时间")
    private LocalDateTime createTime;

    @ApiModelProperty(value = "修改时间")
    private LocalDateTime updateTime;

    @ApiModelProperty(value = "资源状态 0.删除 1.正常")
    private Integer status;


}

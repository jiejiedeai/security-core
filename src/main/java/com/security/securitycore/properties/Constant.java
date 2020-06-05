package com.security.securitycore.properties;

public class Constant {

    /** 过滤器编码 **/
    public static final String FILTER_ENCODING="UTF-8";

    public static final String LOGIN_MOBILEIN="/auth/mobileIn";

    /** 最大session数量 **/
    public static final int MAXIMUM_SESSIONS =1;

    /** security 的中文提示认证 **/
    public static final String MESSAGE_ZH_CN="classpath:org/springframework/security/messages_zh_CN";

    /** security 在redis中资源对应角色的的key **/
    public static final String KEY = "security_resource_key";

}

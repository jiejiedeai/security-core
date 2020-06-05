package com.security.securitycore.security.authority;


import com.security.securitycore.properties.Constant;
import com.security.securitycore.properties.SecurityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class UrlRedisSecurityMetadataSource implements FilterInvocationSecurityMetadataSource, InitializingBean {

    protected RedisTemplate redisTemplate;

    //    protected SecurityMetadataSourceSupport securityMetadataSourceSupport;
    protected List<SecurityMetadataSourceSupport> securityMetadataSourceSupports = new ArrayList<>();

    @Autowired
    private SecurityProperties securityProperties;

    public UrlRedisSecurityMetadataSource(RedisTemplate redisTemplate) {
        this.redisTemplate=redisTemplate;
    }

    /**
     * Bean初始化完成后执行，用于从数据库中加载资源的权限信息
     */
    @PostConstruct
    public void init() {
//        SecurityMetadataSourceSupport support = super.securityMetadataSourceSupport;
        List<SecurityMetadataSourceSupport> supports =this.securityMetadataSourceSupports;
        if (!CollectionUtils.isEmpty(supports)){
            this.refresh();
        }
    }

    /**
     * 从Redis中获取当前Url所有需要的角色权限信息
     * 如果找不到且当前url没有再配置为开放，，表示当前Url没有配置权限
     * <p>
     * 在决策管理器中会对当前Url所需的权限进行校验，如果为OPEN则直接放行，交给下一个过滤器进行处理
     *
     * @param object
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        final HttpServletRequest request = ((FilterInvocation) object).getRequest();
        String requestURI = request.getRequestURI();
        log.info("当前请求:{}", requestURI);

        /**
         * 不登录既可访问的几口
         */
        List<String> anonymousList =Arrays.asList(securityProperties.getAnonymous());
        /**
         * 获取放行的静态资源
         */
        List<String> statics =Arrays.asList(securityProperties.getStatics());
        /**
         * 登录不需要检验权限的接口
         */
        List<String> permitUrls =Arrays.asList(securityProperties.getPermits());
        List<String> perimtAll = new ArrayList<>();
        perimtAll.addAll(statics);
        perimtAll.addAll(permitUrls);
        perimtAll.addAll(anonymousList);
        if (!CollectionUtils.isEmpty(perimtAll)) {
            AntPathMatcher antPathMatcher = new AntPathMatcher();
            long res = perimtAll.stream().filter(pattern -> {
                return antPathMatcher.match(pattern, requestURI);
            }).count();
            /**
             * 返回空list即不进行权限校验，直接放行
             */
            if (res > 0) {
                log.info("开放接口:{}", requestURI);
                return null;
            }
        }

        Collection<ConfigAttribute> configAttributes = getConfigAttributesByKey(requestURI);
        if (!CollectionUtils.isEmpty(configAttributes)) {
            log.info("redis 中的权限信息:{}", configAttributes.toString());
            return configAttributes;
        }

        /** 如果在redis中没有改请求对应的角色配置信息 并且此开关是true 那么就无法访问**/
        if (!securityProperties.isNoMatcherPermit()) {
            log.info("请求未授权:{}", requestURI);
            Collection<ConfigAttribute> any = new ArrayList<>();
            any.add(new SecurityConfig("unauthorized"));
            return any;
        }
        return null;
    }

    /**
     * 用于校验ConfigAttribute是否可用
     *
     * @return
     */
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();
        allAttributes.addAll(getConfigAttributes());
        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
    }

    public List<SecurityMetadataSourceSupport> getSecurityMetadataSourceSupports() {
        return securityMetadataSourceSupports;
    }

    public void setSecurityMetadataSourceSupports(SecurityMetadataSourceSupport securityMetadataSourceSupports) {
        this.securityMetadataSourceSupports.add(securityMetadataSourceSupports);
    }

    /**
     * 将资源的权限信息存储到Redis, 存到redis之前会先清空旧的权限信息
     *
     * @param list
     * @return 资源总数
     */
    public int reloadConfigAttributes(List<UserAuthority> list) {
        Object[] hashKeys = redisTemplate.opsForHash().keys(Constant.KEY).toArray();
        if (hashKeys != null && hashKeys.length > 0) {
            redisTemplate.opsForHash().delete(Constant.KEY, hashKeys);
        }
        if (CollectionUtils.isEmpty(list)) {
            return 0;
        }
        list.stream().forEach(userAuthority -> {
            redisTemplate.opsForHash().put(Constant.KEY, userAuthority.getUri(), userAuthority.getAuthorities());
        });
        return list.size();
    }

    /**
     * 获取所有资源的角色名称
     *
     * @return
     */
    public Collection<ConfigAttribute> getConfigAttributes() {
        return getConfigAttributeFromRedis(redisTemplate.opsForHash().keys(Constant.KEY));
    }

    /**
     * 获取指定资源需要的角色名称
     *
     * @param hashKey 资源url
     * @return
     */
    public Collection<ConfigAttribute> getConfigAttributesByKey(String hashKey) {
        if (!redisTemplate.opsForHash().hasKey(Constant.KEY, hashKey)) {
            return Collections.emptyList();
        }
        return getConfigAttributeFromRedis(Arrays.asList(hashKey));
    }

    /**
     * 从redis中获取所有的资源权限信息
     *
     * @return
     */
    public Collection<ConfigAttribute> getConfigAttributeFromRedis(Collection<? extends String> hashKeys) {
        List<List<Integer>> resourceRoleList = redisTemplate.opsForHash().multiGet(Constant.KEY, hashKeys);
        List<Integer> roleIdList = new ArrayList<>();
        resourceRoleList.stream().forEach(roles -> {
            roleIdList.addAll(roles);
        });
        return roleIdList.stream()
                .map(role -> {
                    return new SecurityConfig(role.toString());
                }).distinct().collect(Collectors.toList());
    }

    /**
     * 刷新资源权限信息到redis
     *
     * @return 刷新的资源总数
     */
    public int refresh() {
        List<UserAuthority> userAuthorities = new ArrayList<>();
        for (SecurityMetadataSourceSupport support : securityMetadataSourceSupports){
            userAuthorities.addAll(support.getAllAuthority());
        }
//        List<UserAuthority> userAuthorities = securityMetadataSourceSupport.getAllAuthority();
        if(userAuthorities != null){
            userAuthorities = userAuthorities.stream().filter(u-> !StringUtils.isEmpty(u.getUri())).collect(Collectors.toList());
        }
        if (CollectionUtils.isEmpty(userAuthorities)) {
            userAuthorities = Collections.emptyList();
        }
        return reloadConfigAttributes(userAuthorities);
    }
}

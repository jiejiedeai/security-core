package com.security.securitycore.security.config;

import com.security.securitycore.properties.Constant;
import com.security.securitycore.properties.SecurityProperties;
import com.security.securitycore.security.authority.DynamicSecurityInterceptor;
import com.security.securitycore.security.filter.image.ValiateImageCodeFilter;
import com.security.securitycore.security.filter.sms.ValidateSmsCodeFilter;
import com.security.securitycore.security.handler.CustomLogoutSuccessHandler;
import com.security.securitycore.security.handler.CustomerAuthenticationFailureHandler;
import com.security.securitycore.security.handler.CustomerAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.web.filter.CharacterEncodingFilter;

import javax.annotation.Resource;
import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //系统配置
    @Autowired
    private SecurityProperties securityProperties;

    //自定义登录成功
    @Autowired
    private CustomerAuthenticationSuccessHandler customerAuthenticationSuccessHandler;

    //自定义登录失败处理
    @Autowired
    private CustomerAuthenticationFailureHandler customerAuthenticationFailureHandler;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private CustomLogoutSuccessHandler customLogoutSuccessHandler;

    @Autowired
    private ValiateImageCodeFilter valiateImageCodeFilter;

    @Autowired
    private ValidateSmsCodeFilter validateSmsCodeFilter;

    @Autowired
    private MobileAuthenticationConfig mobileAuthenticationConfig;

    @Resource(name = "userDetailServiceImpl")
    private UserDetailsService userDetailsService;

    @Autowired
    private InvalidSessionStrategy invalidSessionStrategy;

    @Autowired
    private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

    @Value("${server.servlet.session.cookie.name}")
    private String JSESSIONID;

    @Autowired
    private DynamicSecurityInterceptor dynamicSecurityInterceptor;

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 加载spring自己的中文认证提示信息
     * @return
     */
    @Bean
    public ReloadableResourceBundleMessageSource reloadableResourceBundleMessageSource(){
        ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
        //后缀的.properties不要加 在ReloadableResourceBundleMessageSource中会自动拼接后缀
        messageSource.setBasename(Constant.MESSAGE_ZH_CN);
        return messageSource;
    }

    /**
     * 解决退出session不清空问题 此处初始化其他地方就可以依赖到
     * @return
     */
    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }

    /**
     * 记住我功能
     * @return
     */
    @Bean
    public JdbcTokenRepositoryImpl jdbcTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        //启动项目时候自动创建记住我功能数据库表 只能首次使用 第二次使用会报错因为表已经存在
//        tokenRepository.setCreateTableOnStartup(true);
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors(withDefaults());// by default uses a Bean by the name of corsConfigurationSource
        //关闭csrf 跨站请求伪造 用于开发测试
        http.csrf().disable();

        //图形校验过滤器
        http.addFilterBefore(valiateImageCodeFilter,UsernamePasswordAuthenticationFilter.class);
        //验短信验证过滤器 短信认证过滤器在UsernamePasswordAuthenticationFilter之后
        http.addFilterBefore(validateSmsCodeFilter,UsernamePasswordAuthenticationFilter.class);
        //动态权限放在security 拦截器之后判断当前请求url对应的角色列表是否包含用户所拥有的角色列表
        http.addFilterAfter(dynamicSecurityInterceptor, FilterSecurityInterceptor.class);
        http
                //使用form表单post方式进行登录
                .formLogin()
                //如果未认证过会走此接口包装了返回json结果给前端提示未认证
                .loginPage(securityProperties.getLoginPage())
                //真正的登录接口 UsernamePasswordAuthenticationFilter默认登录接口是/login 此处我们可以自定义接口但不一定存在
                .loginProcessingUrl(securityProperties.getLoginProcessingUrl())
                //自定登录成功处理
                .successHandler(customerAuthenticationSuccessHandler)
                //自定义登录失败处理
                .failureHandler(customerAuthenticationFailureHandler)
                .and()
                //允许不登陆就可以访问的方法，多个用逗号分隔
                .authorizeRequests()
                .antMatchers(
                        securityProperties.getAnonymous()
                ).permitAll()
                //退出
                .and().logout().permitAll()
                //其他的需要授权后访问
                .and().authorizeRequests().anyRequest().authenticated();
        //手机认证过滤器在UsernamePasswordAuthenticationFilter之后并将手机认证放在过滤器链上
        http.apply(mobileAuthenticationConfig);
        //记住我
        http.rememberMe()
                .rememberMeParameter(securityProperties.getRemeberMeParameterName())
                .rememberMeCookieName(securityProperties.getRemeberMeParameterName())
                .userDetailsService(userDetailsService)
                //保存登录信息
                .tokenRepository(jdbcTokenRepository())
                //记住我有效时长
                .tokenValiditySeconds(securityProperties.getTokenValiditySeconds());
        //单用户登录，如果有一个登录了，同一个用户在其他地方登录将前一个剔除下线
        http
                .sessionManagement()
                //session过期提示
                .invalidSessionStrategy(invalidSessionStrategy)
                .maximumSessions(Constant.MAXIMUM_SESSIONS)
                //当session登录超过指定值后会调用这个类
                .expiredSessionStrategy(sessionInformationExpiredStrategy);
                //超过当前最大session值后就提示
//                .maxSessionsPreventsLogin(true);
        //退出时情况cookies
        http
                .logout()
                .logoutUrl(securityProperties.getLogoutUrl())
                .logoutSuccessHandler(customLogoutSuccessHandler)
                .deleteCookies(JSESSIONID);

        //解决中文乱码问题
        CharacterEncodingFilter filter = new CharacterEncodingFilter();
        filter.setEncoding(Constant.FILTER_ENCODING);
        filter.setForceEncoding(true);
        http.addFilterBefore(filter, CsrfFilter.class);
    }

    /**
     * 一般针对静态资源进行放行
     * @param web
     * @throws Exception
     */
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(securityProperties.getStatics());
    }

}

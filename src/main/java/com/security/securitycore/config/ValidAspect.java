package com.security.securitycore.config;

import com.security.securitycore.model.JsonResult;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.hibernate.validator.internal.engine.path.PathImpl;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.stereotype.Component;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.ObjectError;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.ValidatorFactory;
import javax.validation.executable.ExecutableValidator;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;

/**
 * 
 * 项目名称：module-qualify-stock    
 * 类名称：ValidAspect    
 * 类描述：全局aop 扫描spring校验框架并处理校验javabean或者参数失败后提示    
 * 创建人：乔鹏    
 * 创建时间：2018年4月3日 下午1:37:32    
 * 修改人：  
 * 修改时间：   
 * 修改备注：
 */
@Aspect
@Component
public class ValidAspect{
	private ParameterNameDiscoverer parameterNameDiscoverer = new LocalVariableTableParameterNameDiscoverer();
    private final ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
    private final ExecutableValidator validator = factory.getValidator().forExecutables();
    private <T> Set<ConstraintViolation<T>> validMethodParams(T obj, Method method, Object[] params) {
        return validator.validateParameters(obj, method, params);
    }

    //定义切面
    @Pointcut(value="execution(* com.security.securitycore.controller.*.*(..))")
    public void valid() {
    }
    //环绕通知,环绕增强，相当于MethodInterceptor
    @Around("valid()")
    public Object arround(ProceedingJoinPoint pjp) throws Throwable {
        //方法环绕start
        //取参数，如果没参数，那肯定不校验了
        Object[] objects = pjp.getArgs();
        if (objects.length == 0) {
            return pjp.proceed();
        }
        /**************************校验JavaBean*************************/
        //校验封装好的 javabean 寻找带BindingResult参数的方法，然后判断是否有error，如果有则是校验不通过
        for (Object object : objects) {
            if (object instanceof BeanPropertyBindingResult) {
                //有校验
                BeanPropertyBindingResult result = (BeanPropertyBindingResult) object;
                if (result.hasErrors()) {
                    List<ObjectError> list = result.getAllErrors();
                    for (ObjectError error : list) {
                        return JsonResult.error(error.getDefaultMessage());
                    }
                }
            }
        }
        /**************************校验普通参数*************************/
        //  获得切入目标对象
        Object target = pjp.getThis();
        // 获得切入的方法
        Method method = ((MethodSignature) pjp.getSignature()).getMethod();
        // 执行校验，获得校验结果
        Set<ConstraintViolation<Object>> validResult = validMethodParams(target, method, objects);
        //如果有校验不通过的
        if (!validResult.isEmpty()) {
            String[] parameterNames = parameterNameDiscoverer.getParameterNames(method); // 获得方法的参数名称
            for(ConstraintViolation<Object> constraintViolation : validResult) {
                PathImpl pathImpl = (PathImpl) constraintViolation.getPropertyPath();  // 获得校验的参数路径信息
                int paramIndex = pathImpl.getLeafNode().getParameterIndex(); // 获得校验的参数位置
                String paramName = parameterNames[paramIndex];  // 获得校验的参数名称
                //校验信息
                Class<?>[] classes = method.getReturnType().getClasses();
                return JsonResult.error(constraintViolation.getMessage());
            }
            //返回第一条
        }
        return pjp.proceed();
    }

}

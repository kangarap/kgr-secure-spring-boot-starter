package com.kgr.security.config;

import cn.hutool.json.JSONUtil;
import com.kgr.security.annotation.SecureTransmission;
import com.kgr.security.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.Objects;
import java.util.Optional;

/**
 * @author kgr
 */
@Aspect
@Order(-1)
@Component
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "kgr.secure", value = "enabled", havingValue = "true")
public class GetDeleteDecryptAspect {

    private final SecureProperties secureProperties;

    /**
     * 对get、delete方法进行解密
     * @param point
     * @return
     * @throws Throwable
     */
    @Around("@annotation(com.kgr.security.annotation.SecureTransmission) && " + "(@annotation(org.springframework.web.bind.annotation.GetMapping) || @annotation(org.springframework.web.bind.annotation.DeleteMapping))")
    public Object aroundMethod(ProceedingJoinPoint point) throws Throwable {

        MethodSignature signature = (MethodSignature) point.getSignature();
        Method method = signature.getMethod();

        // 获取到请求的参数列表
        Object[] args = point.getArgs();
        // 是否需要解密
        if (method.isAnnotationPresent(SecureTransmission.class) && method.getAnnotation(SecureTransmission.class).decrypt()) {
            try {
                decrypt(args);
            } catch (Exception e) {
                e.printStackTrace();
                log.error("切面解密异常, method :【" + method.getName() + "】, 异常：" + e.getMessage());
            }
        }
        // 执行将解密的结果交给控制器进行处理，并返回处理结果
        return point.proceed(args);
    }

    /**
     * 前端对请求参数进行加密，最终将这个加密的字符串已 localhost:8080?data=xxx这样的方式进行传递
     * data的数据进行解密最终得到解密后的数据
     * @param args
     * @throws Exception
     */
    public void decrypt(Object[] args) {
        ServletRequestAttributes sc = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = sc.getRequest();
        String data = request.getParameter("data");
        log.info("待解密字符串{}: ", data);

        if (ObjectUtils.isEmpty(data)) {
            return;
        }

        // 使用Optional从请求头中获取 sm4对称密钥 的值
        String sm4Key = Optional.ofNullable(request.getHeader(secureProperties.getHeaderEncryptKeyName())).orElse(null);

        if(Objects.isNull(sm4Key)) {
            // 没有对称密钥，就直接进行 sm2 的非对称解密
            data = CryptoUtils.sm2Decrypt(data, secureProperties.getSecretKey());
        }else
        {
            // 将请求头中的sm4对应值 先用sm2解密，然后再用解密后的sm4对数据进行解密
            String sm4DecryptData = CryptoUtils.sm2Decrypt(sm4Key, secureProperties.getSecretKey());
            data = CryptoUtils.sm4Decrypt(data, sm4DecryptData);
        }

        // 并替换原本的参数
        args[0] = JSONUtil.toBean(data, args[0].getClass());

    }
}

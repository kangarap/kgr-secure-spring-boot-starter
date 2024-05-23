package com.kgr.security.config;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.kgr.security.annotation.SecureTransmission;
import com.kgr.security.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.util.Objects;
import java.util.Optional;

/**
 * @description: 响应加密
 */

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "kgr.secure", value = "enabled", havingValue = "true")
public class SecureResponseBodyAdvice implements ResponseBodyAdvice {


    private final SecureProperties secureProperties;

    /**
     * 这个方法用来判断什么样的接口需要加密
     * @param returnType
     * @param converterType
     * @return boolean 返回类型
     */
    @Override
    public boolean supports(MethodParameter returnType, Class converterType) {
        return returnType.hasMethodAnnotation(SecureTransmission.class) && returnType.getMethodAnnotation(SecureTransmission.class).encrypt();

    }


    /**
     * 这个方法会在数据响应之前执行，也就是我们先对响应数据进行二次处理，处理完成后，才会转成 json 返回
     * @param body
     * @param returnType
     * @param selectedContentType
     * @param selectedConverterType
     * @param request
     * @param response
     * @return
     */
    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType, Class selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {
        log.info("对方法 :【" + returnType.getMethod().getName() + "】返回数据进行加密");

        // 一般返回都是json格式
        JSONObject jsonObject = JSONUtil.parseObj(body);
        Object result = jsonObject.getObj("data", Object.class);

        if (Objects.nonNull(result)) {
            try {
                // 使用Optional从请求头中获取 sm4对称密钥 的值
                String sm4Key = Optional.ofNullable(request.getHeaders().get(secureProperties.getHeaderEncryptKeyName()))
                        .flatMap(keys -> keys.stream().findFirst())
                        .orElse(null);

                if(Objects.isNull(sm4Key)) {
                    // 没有对称密钥，用默认密钥
                    sm4Key = secureProperties.getHeaderEncryptKeyValue();
                }else
                {
                    // 先将请求头中的sm4解出来
                    sm4Key = CryptoUtils.sm2Decrypt(sm4Key, secureProperties.getSecretKey());
                }

                // 用sm4对数据加密
                result = CryptoUtils.sm4Encrypt(result.toString(), sm4Key);

                jsonObject.set("data", result);
            } catch (Exception e) {
                log.error("对方法 :【" + returnType.getMethod().getName() + "】返回数据进行解密出现异常：" + e.getMessage());
            }
        }
        return jsonObject;
    }



}


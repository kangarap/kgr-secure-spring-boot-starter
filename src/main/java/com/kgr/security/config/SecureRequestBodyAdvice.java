package com.kgr.security.config;

import cn.hutool.core.date.DateUnit;
import cn.hutool.core.date.DateUtil;
import cn.hutool.json.JSONUtil;
import com.kgr.security.annotation.SecureTransmission;
import com.kgr.security.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

/**
 * @description: 请求参数解密，针对post请求
 */

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "kgr.secure", value = "enabled", havingValue = "true")
public class SecureRequestBodyAdvice implements RequestBodyAdvice {


    private final SecureProperties secureProperties;


    /**
     * 方法上有SecureTransmission注解的，并且decrypt=true，进入此拦截器
     * 此处如果返回false , 则不执行当前Advice的业务
     */
    @Override
    public boolean supports(MethodParameter returnType, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {

        return returnType.hasMethodAnnotation(SecureTransmission.class) && returnType.getMethodAnnotation(SecureTransmission.class).decrypt();
    }

    /**
     * 读取参数前执行
     */
    @SneakyThrows(Exception.class)
    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter returnType, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return new MyHttpInputMessage(inputMessage, returnType);
    }

    /**
     * 读取参数后执行
     * 转换之后，执行此方法，解密，赋值
     * @param body          spring解析完的参数
     * @param inputMessage  输入参数
     * @param returnType     参数对象
     * @param targetType    参数类型
     * @param converterType 消息转换类型
     * @return 真实的参数
     */
    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter returnType, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }


    /**
     * 如果body为空，转为空对象
     *
     * @param body          spring解析完的参数
     * @param inputMessage  输入参数
     * @param returnType     参数对象
     * @param targetType    参数类型
     * @param converterType 消息转换类型
     * @return 真实的参数
     */
    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter returnType, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    /**
     * 封装一个自己的HttpInputMessage
     */
    class MyHttpInputMessage implements HttpInputMessage {

        private HttpHeaders headers;
        private InputStream body;
        private MethodParameter returnType;

        public MyHttpInputMessage(HttpInputMessage inputMessage, MethodParameter returnType) throws Exception {

            this.headers = inputMessage.getHeaders();
            this.body = inputMessage.getBody();

            /**
             * 对post提交的加密参数解密
             */
            if (returnType.hasMethodAnnotation(PostMapping.class)) {
                // 使用Optional从请求头中获取 sm4对称密钥 的值
                String sm4Key = Optional.ofNullable(inputMessage.getHeaders().get(secureProperties.getHeaderEncryptKeyName()))
                        .flatMap(keys -> keys.stream().findFirst())
                        .filter(value -> !value.trim().isEmpty())
                        .orElseThrow(() -> new RuntimeException("请求密钥不允许为空"));

                String sign = Optional.ofNullable(inputMessage.getHeaders().get("Sign"))
                        .flatMap(keys -> keys.stream().findFirst())
                        .filter(value -> !value.trim().isEmpty())
                        .orElseThrow(() -> new RuntimeException("签名不允许为空"));

                Long timestamp = Optional.ofNullable(inputMessage.getHeaders().get("Timestamp"))
                        .flatMap(keys -> keys.stream().findFirst())
                        .filter(value -> !value.trim().isEmpty())
                        .map(Long::new)
                        .orElseThrow(() -> new RuntimeException("时间戳不允许为空"));


                //重放时间限制（单位秒）
                long difference = DateUtil.between(DateUtil.date(), DateUtil.date(timestamp * 1000), DateUnit.SECOND);

                if (difference > secureProperties.getSignTimeout()) {
                    throw new RuntimeException("无效请求, 签名已过期");
                }

                // 1. 将请求头中的sm4对应值 先用sm2解密, 获取sm4的明文
                String sm4DecryptData = CryptoUtils.sm2Decrypt(sm4Key, secureProperties.getSecretKey());

                // 2. 然后用解密后的sm4对数据进行解密
                String verifyData = easpData(convertInputStreamToString(inputMessage.getBody()));
                verifyData = CryptoUtils.sm4Decrypt(verifyData, sm4DecryptData);

                // 3. 解密后参数 重新生成签名来 验证sign, 不要忘记有个前缀
                String newSign = CryptoUtils.sm4Encrypt(secureProperties.getSignPrefix() + timestamp + verifyData, sm4DecryptData);

                if(!newSign.equals(sign)) {
                    throw new RuntimeException("无效请求，签名验证失败");
                }


                this.body = new ByteArrayInputStream(verifyData.getBytes(StandardCharsets.UTF_8));
            }
        }

        @Override
        public InputStream getBody() {
            return body;
        }

        @Override
        public HttpHeaders getHeaders() {
            return headers;
        }

    }

    public String easpData(String requestData) throws RuntimeException {

        if (Objects.isNull(requestData) || "".equals(requestData)) {
            return "";
        }

        String start = "requestData";

        if (!requestData.contains(start)) {
            throw new RuntimeException("参数【requestData】缺失异常！");
        }

        return JSONUtil.parseObj(requestData).getStr(start);
    }


    private String convertInputStreamToString(InputStream inputStream) throws Exception {
        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
        }
        return stringBuilder.toString();
    }

}

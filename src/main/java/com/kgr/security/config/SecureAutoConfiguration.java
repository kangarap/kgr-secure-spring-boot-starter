package com.kgr.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import java.util.Objects;

@Configuration
@ComponentScan("com.kgr.security.config")
@EnableConfigurationProperties(SecureProperties.class)
@Slf4j
public class SecureAutoConfiguration {

    public SecureAutoConfiguration(SecureProperties secureProperties) {

        String headerEncryptKeyName = secureProperties.getHeaderEncryptKeyName();
        String headerEncryptKeyValue = secureProperties.getHeaderEncryptKeyValue();


        if (Objects.isNull(headerEncryptKeyName) && Objects.isNull(headerEncryptKeyValue)) {
            log.debug("未配置 kgr.secure.header-encrypt-key-name");

            throw new RuntimeException("请在配置文件中添加kgr.secure.header-encrypt-key-value项");
        }
    }

}

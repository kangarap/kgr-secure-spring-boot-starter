package com.kgr.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "kgr.secure")
public class SecureProperties {

    private String headerEncryptKeyName;
    private String headerEncryptKeyValue;
    private String secretKey;
    private Long signTimeout;
    private String signPrefix;
    private Boolean enabled;
}

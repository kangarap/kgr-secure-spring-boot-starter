package com.kgr.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author kgr
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface SecureTransmission {

    /**
     * 是否加密返回数据，默认否
     */
    boolean encrypt() default false;

    /**
     * 是否解密参数，默认否
     */
    boolean decrypt() default false;
}

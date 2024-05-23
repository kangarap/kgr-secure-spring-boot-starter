package com.kgr.security.util;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.*;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SM4;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 加密方法工具类
 */
public class CryptoUtils {

    /**
     * 国密sm2加密
     *
     * @param text      内容
     * @param publicKey 公钥
     * @return 结果 非压缩密文
     */
    public static String sm2Encrypt(String text, String publicKey) {
        return SmUtil.sm2(null, publicKey).encryptBcd(text, KeyType.PublicKey);
    }

    /**
     * 国密sm2解密 非压缩密文
     *
     * @param text       内容
     * @param privateKey 私钥
     * @return 结果 明文
     */
    public static String sm2Decrypt(String text, String privateKey) {
        return StrUtil.utf8Str(SmUtil.sm2(privateKey, null).decryptFromBcd(text, KeyType.PrivateKey));
    }

    /**
     * 国密sm3加密
     *
     * @param text 内容
     * @return 结果
     */
    public static String sm3Encrypt(String text) {
        return SmUtil.sm3(text);
    }

    /**
     * 国密sm3加密
     *
     * @param text 内容
     * @param salt 盐
     * @return 结果
     */
    public static String sm3Encrypt(String text, String salt) {
        return SmUtil.sm3().setSalt(salt.getBytes(StandardCharsets.UTF_8)).digestHex(text, CharsetUtil.CHARSET_UTF_8);
    }

    /**
     * 国密sm4加密
     *
     * @param text 内容
     * @param key  密钥
     * @return 结果 返回十六进制密文
     */
    public static String sm4Encrypt(String text, String key) {

        return sm4Encrypt(text, key, "", "ECB", Padding.PKCS5Padding.name());
    }

    /**
     *  国密sm4加密,支持自定义参数
     * @param text
     * @param key
     * @param iv
     * @param mode
     * @param padding
     * @return 返回十六进制密文
     */
    public static String sm4Encrypt(String text, String key, String iv, String mode, String padding) {
        return new SM4(mode, padding,
                getKey(key),
                iv.getBytes(CharsetUtil.CHARSET_UTF_8))
                .encryptHex(text);
    }

    /**
     * 国密sm4加密
     *
     * @param text 内容
     * @param key  密钥
     * @return 结果 返回Base64密文
     */
    public static String sm4EncryptBase64(String text, String key) {

        return sm4EncryptBase64(text, key, "", "ECB", Padding.PKCS5Padding.name());
    }

    /**
     *   国密sm4加密 支持自定义参数
     * @param text 内容
     * @param key 密钥
     * @param iv 偏移量
     * @param mode 模式("ECB","CBC")
     * @param padding  填充模式
     * @return 返回Base64密文
     */
    public static String sm4EncryptBase64(String text, String key, String iv, String mode, String padding) {
        return new SM4(mode, padding,
                getKey(key),
                iv.getBytes(CharsetUtil.CHARSET_UTF_8))
                .encryptBase64(text);
    }


    /**
     * 密钥转byte数组
     * @param key
     * @return
     */
    private static byte[] getKey(String key) {
        if (key.length() == 32) {
            return HexUtil.decodeHex(key);
        }
        if (key.length() == 16) {
            return key.getBytes();
        }
        return null;
    }

    /**
     * 国密sm4解密
     *
     * @param text 内容
     * @param key  密钥
     * @return 结果 返回明文
     */
    public static String sm4Decrypt(String text, String key) {
        return sm4Decrypt(text,key,"", "ECB", Padding.PKCS5Padding.name());
    }


    /**
     *
     * @param text 内容
     * @param key 密钥
     * @param iv 偏移量
     * @param mode 模式("ECB","CBC")
     * @param padding  填充模式
     * @return 返回明文
     */
    public static String sm4Decrypt(String text, String key,String iv, String mode, String padding) {
        return   new SM4(mode, padding,
                getKey(key),
                iv.getBytes(CharsetUtil.CHARSET_UTF_8))
                .decryptStr(text);
    }

    /**
     * md5
     * 推荐使用sha256
     * @param text 内容
     * @return 结果
     */
    @Deprecated
    public static String md5(String text) {
        return SecureUtil.md5(text);
    }

    /**
     * sha256
     *
     * @param text 内容
     * @return 结果
     */
    public static String sha256(String text) {
        MessageDigest messageDigest;
        String encodeStr = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(text.getBytes(StandardCharsets.UTF_8));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return encodeStr;
    }

    /**
     * 字节数组转十六进制
     * @param bytes
     * @return
     */
    private static String byte2Hex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        String temp;
        for (byte aByte : bytes) {
            temp = Integer.toHexString(aByte & 0xFF);
            if (temp.length() == 1) {
                //1得到一位的进行补0操作
                stringBuilder.append("0");
            }
            stringBuilder.append(temp);
        }
        return stringBuilder.toString();
    }




    /**
     * rsa加密
     * 推荐使用sm2
     * @param text      内容
     * @param publicKey 公钥
     * @return 结果
     */
    @Deprecated
    public static String rsaEncrypt(String text, String publicKey) {
        return new RSA(null, publicKey).encryptHex(text, KeyType.PublicKey);
    }

    /**
     * rsa解密
     * 推荐使用sm2
     * @param text       内容
     * @param privateKey 私钥
     * @return 结果
     */
    @Deprecated
    public static String rsaDecrypt(String text, String privateKey) {
        return new RSA(privateKey, null).decryptStr(text, KeyType.PrivateKey);
    }

    /**
     * aes加密 (默认AES/ECB/PKCS5Padding)
     * 推荐使用sm4
     * @param text 内容
     * @param key  密钥
     * @return 结果
     */
    @Deprecated
    public static String aesEncrypt(String text, String key) {
        return new AES(Mode.ECB, Padding.PKCS5Padding, key.getBytes(CharsetUtil.CHARSET_UTF_8)).encryptHex(text);
    }

    /**
     * aes加密
     * 推荐使用sm4
     * @param text 内容
     * @param key 密钥
     * @param iv 偏移量
     * @param mode
     * @param padding
     * @return 结果
     */
    @Deprecated
    public static String aesEncrypt(String text, String key, String iv, String mode, String padding) {
        return new AES(mode, padding,
                key.getBytes(CharsetUtil.CHARSET_UTF_8),
                iv.getBytes(CharsetUtil.CHARSET_UTF_8))
                .encryptBase64(text);
    }

    /**
     * aes解密 (默认AES/ECB/PKCS5Padding)
     * 推荐使用sm4
     * @param text 内容
     * @param key  密钥
     * @return 结果
     */
    @Deprecated
    public static String aesDecrypt(String text, String key) {
        return new AES(Mode.ECB, Padding.PKCS5Padding, key.getBytes(CharsetUtil.CHARSET_UTF_8)).decryptStr(text);
    }

    /**
     * aes解密
     * 推荐使用sm4
     * @param text
     * @param key
     * @param iv
     * @param mode
     * @param padding
     * @return 结果
     */
    @Deprecated
    public static String aesDecrypt(String text, String key, String iv, String mode, String padding) {
        return new AES(mode, padding, key.getBytes(CharsetUtil.CHARSET_UTF_8), iv.getBytes(CharsetUtil.CHARSET_UTF_8)).decryptStr(text);
    }

    /**
     * 生成RSA密钥对
     */
    @Deprecated
    public static KeyPair createKeyPairRSA() {
        return SecureUtil.generateKeyPair("RSA");
    }

    /**
     * 生成SM2密钥对
     */
    public static KeyPair createKeyPairSM2() {
        return SecureUtil.generateKeyPair("SM2");
    }

    /**
     * 返回适配前端sm-crypto的SM2公钥
     * @param keyPair
     * @return 返回适配前端sm-crypto的SM2公钥
     */
    public static  String getSm2PublicQ(KeyPair keyPair) {
        //这里得到未压缩公钥  公钥的第一个字节用于表示是否压缩 02或者03表示是压缩公钥,04表示未压缩公钥
        return Base64.encode(((BCECPublicKey) keyPair.getPublic()).getQ().getEncoded(false));
    }
    /**
     * 返回适配前端sm-crypto的SM2私钥
     * @param keyPair
     * @return 返回适配前端sm-crypto的SM2私钥
     */
    public static  String getSm2PrivateD(KeyPair keyPair) {
        return  Base64.encode(((BCECPrivateKey) keyPair.getPrivate()).getD().toByteArray());
    }

    public static void main(String[] args) {

//        BHzIsWjxRinBfh403CsCyG/KplJfjlvbYf6SH7AwdLj5KgubveuCDpL0A/fbpEAL/2WMT7ZiC06CqQk/TScp7E4=

//        AO87VuLgWm9+jP5X2Chx/YezTNCczZUfNwfHSDEuCj9E

//        KeyPair keyPairSM2 = createKeyPairSM2();
//        System.out.println(getSm2PublicQ(keyPairSM2));
//        System.out.println(getSm2PrivateD(keyPairSM2));
        String test = "{\n" +
                "\"username\":\"admin\",\n" +
                "\"deptId\":\"1250500000\",\n" +
                "\"userId\":1,\n" +
                "\"phone\":\"15151515151\"\n" +
                "}";

        System.out.println(sm2Encrypt(test,"BHzIsWjxRinBfh403CsCyG/KplJfjlvbYf6SH7AwdLj5KgubveuCDpL0A/fbpEAL/2WMT7ZiC06CqQk/TScp7E4="));
//        System.out.println(sm2Decrypt("","AO87VuLgWm9+jP5X2Chx/YezTNCczZUfNwfHSDEuCj9E"));
    }


}

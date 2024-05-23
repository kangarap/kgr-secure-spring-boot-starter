### 自用的加密解密
> 总是被安全扫出各种问题，😅所以直接封装一个模块出来

对于post请求， 格式为{"requestData": "加密的内容"}

对于get，delete请求，格式为路由拼接data参数，如 localhost:8080/api/test?data=加密的内容


### 食用方式

1. pom 引入依赖
```xml

<repositories>
    <repository>
        <id>github-repo</id>
        <name>The Repository on Github</name>
        <url>https://kangarap.github.io/kgr-secure-spring-boot-starter/maven-repo/</url>
    </repository>
</repositories>


<dependency>
    <groupId>com.kgr</groupId>
    <artifactId>kgr-secure-spring-boot-starter</artifactId>
    <version>0.0.1</version>
</dependency>
```

2. 配置文件中添加

```yaml
kgr:
  secure:
    # 是否开启
    enabled: true
    # 请求头部的 sm4 密钥对应的键名
    header-encrypt-key-name: Kd-Encrypt-Key
    # 当获取不到 header-encrypt-key-name 对应的值时，会使用
    header-encrypt-key-value: 06b0c0e0-e0b0-4b0c-80e0-b0c0e0b0c0e0
    # 接口协商采用的sm4私钥              # 公钥 BHzIsWjxRinBfh403CsCyG/KplJfjlvbYf6SH7AwdLj5KgubveuCDpL0A/fbpEAL/2WMT7ZiC06CqQk/TScp7E4=
    #    secret-key: AO87VuLgWm9+jP5X2Chx/YezTNCczZUfNwfHSDEuCj9E
    secret-key: AP3nxJ0LvdjLzM54y9IiWGbiEUQVc5/MLOrTF156mBfA
    # 签名验证超时时间 秒
    sign-timeout: 60
    # 签名前缀
    sign-prefix: Timestamp
```

3. 创建接口测试

UserReqVO
```java
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@ApiModel(description = "用户请求vo")
@Data
public class UserReqVO {

    @ApiModelProperty(value = "用户名", required = true)
    private String username;

    @ApiModelProperty(value = "部门id",required = true)
    private Long deptId;

    @ApiModelProperty(value = "用户id",required = true)
    private Long userId;

    @ApiModelProperty(value = "电话号码",required = true)
    private String phone;
}
```

```text
curl -X POST -H  "Accept:*/*" -H  "Kd-encrypt-key:04d5bd78c9fc8bc45bc3de8f8e9f5060641e49c2a08295c68fee81a711b456fb241c0ed567a5dcfb056e508c8afd4d5624fb37a90b6efc2655816c1a35cba673f2338e951b0060dcb929f9628d7d9128c392ee8e179b9c407a063773191fd12a30ce96e4f7aa30ddd1133b1561d1a3f32262c52c6be708dab7878230e52a472189" -H  "Sign:11111" -H  "Timestamp:11111" -H  "Authorization:Bearer test" -H  "Content-Type:application/json" -d "{\"requestData\":\"3cd8cf2fa66319c368c5384c3d69f269201c5aa396f9b60559dff0200b833c1be4c565e109fafd22d9192ea074ee559864e4e53861de5e0a3fceca46d383fb45700401d5600c516444460dfd7a99c6bc9873e845d7a43a00a95466bd0055c3ccfc878f4f79b6f108ae41d23f04ef0aee\"}" "http://localhost/api/test"
```

### 前端

配置环境中添加 sm2公钥
```
VITE_SM2_PUBLIC_KEY = 'BHzIsWjxRinBfh403CsCyG/KplJfjlvbYf6SH7AwdLj5KgubveuCDpL0A/fbpEAL/2WMT7ZiC06CqQk/TScp7E4='
```

package.json 文件中增加依赖
```json
"sm-crypto": "0.3.11",
"sortablejs": "^1.15.0",
```

写个测试方法
```js
function test() {
    
    let sm2key = import.meta.env.VITE_SM2_PUBLIC_KEY;
        
    // CryptoUtil.js的方法
    let sm4key = createSm4Key();
    
    let encryptKey = sm2Encrypt(sm4key, sm2key);
    
    let q = {
        username: '张三',
    }
    // 时间戳加入头部, 只要10位
    let timestamp = Math.floor(Date.now() / 1000);
    let sign = sm4Encrypt(${前缀}+timestamp + JSON.stringify(q), sm4key);
    
    console.log("随机生成的 sm4key: ", sm4key);
    // 将encryptKey放到请求头中
    console.log("sm2加密后的sm4 放到头部header中：", encryptKey);
    console.log("加密后的请求参数 data：", sm4Encrypt(JSON.stringify(q), sm4key));
    console.log("==================")
    console.log("sign：", sign)
    console.log("时间戳：", timestamp)

}
```


CryptoUtil.js

```js
import { sm2, sm4 } from 'sm-crypto'
import { v4 as uuidV4 } from 'uuid'
/** sm2加密 */
export function sm2Encrypt(text, publicKey) {
  if (!text) {
    return text
  }
  const cipherMode = 1 // 1 - C1C3C2，0 - C1C2C3，默认为1
  if (!publicKey) {
    publicKey = import.meta.env.VITE_APP_SM2_PUBLIC_KEY
  }
  publicKey = base64ToHex(publicKey)
  const result = sm2.doEncrypt(text, publicKey, cipherMode)
  return '04' + result
}

// base64转hex
function base64ToHex(base64) {
  parseInt(atob(base64), 2).toString(16)
  const raw = atob(base64)
  let hex = ''
  for (let i = 0; i < raw.length; i++) {
    const charCode = raw.charCodeAt(i)
    const hexString = charCode.toString(16)
    hex += hexString.padStart(2, '0')
  }
  return hex
}

/** 生成sm4密钥 */
export function createSm4Key() {
  // 生成uuid，去除横杠
  return uuidV4().replace(/[-]/g, '')
}

/** sm4对称加密 */
export function sm4Encrypt(text, key) {
  return sm4.encrypt(text, key)
}

/** sm4解密 */
export function sm4Decrypt(text, key) {
  return sm4.decrypt(text, key)
}
```
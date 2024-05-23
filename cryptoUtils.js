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


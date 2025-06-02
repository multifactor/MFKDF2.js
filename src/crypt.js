const crypto = require('crypto')

function encrypt (data, key) {
  const cipher = crypto.createCipheriv('AES-256-ECB', key, null)
  cipher.setAutoPadding(false)
  return Buffer.concat([cipher.update(data), cipher.final()])
}

function decrypt (data, key) {
  const decipher = crypto.createDecipheriv('AES-256-ECB', key, null)
  decipher.setAutoPadding(false)
  return Buffer.concat([decipher.update(data), decipher.final()])
}

module.exports = { encrypt, decrypt }

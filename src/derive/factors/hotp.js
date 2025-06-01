/**
 * @file MFKDF HOTP Factor Derivation
 * @copyright Multifactor 2022–2025 All Rights Reserved
 *
 * @description
 * Derive HOTP factor for multi-factor key derivation
 *
 * @author Multifactor <support@multifactor.com>
 */
const xor = require('buffer-xor')
const speakeasy = require('speakeasy')

function mod (n, m) {
  return ((n % m) + m) % m
}

/**
 * Derive an MFKDF HOTP factor
 *
 * @example
 * // setup key with hotp factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') })
 * ])
 *
 * // derive key with hotp factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   hotp: mfkdf.derive.factors.hotp(365287)
 * })
 *
 * setup.key.toString('hex') // -> 01…16
 * derive.key.toString('hex') // -> 01…16
 *
 * @param {number} code - The HOTP code from which to derive an MFKDF factor
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Multifactor <support@multifactor.com>
 * @since 0.12.0
 * @memberof derive.factors
 */
function hotp (code) {
  if (!Number.isInteger(code)) throw new TypeError('code must be an integer')

  return async (params) => {
    const target = mod(params.offset + code, 10 ** params.digits)
    const buffer = Buffer.allocUnsafe(4)
    buffer.writeUInt32BE(target, 0)

    return {
      type: 'hotp',
      data: buffer,
      params: async ({ key }) => {
        const pad = Buffer.from(params.pad, 'base64')
        const secret = xor(pad, key.slice(0, Buffer.byteLength(pad)))

        const code = parseInt(
          speakeasy.hotp({
            secret: secret.toString('hex'),
            encoding: 'hex',
            counter: params.counter + 1,
            algorithm: params.hash,
            digits: params.digits
          })
        )

        const offset = mod(target - code, 10 ** params.digits)

        return {
          hash: params.hash,
          digits: params.digits,
          pad: params.pad,
          counter: params.counter + 1,
          offset
        }
      },
      output: async () => {
        return {}
      }
    }
  }
}
module.exports.hotp = hotp

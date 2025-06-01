/**
 * @file Multi-factor Key Derivation
 * @copyright Multifactor 2022–2025 All Rights Reserved
 *
 * @description
 * Derive a multi-factor derived key
 *
 * @author Multifactor <support@multifactor.com>
 */

const Ajv = require('ajv')
const policySchema = require('./policy.json')
const combine = require('../secrets/combine').combine
const recover = require('../secrets/recover').recover
const kdf = require('../kdf').kdf
const { hkdf } = require('@panva/hkdf')
const xor = require('buffer-xor')
const MFKDFDerivedKey = require('../classes/MFKDFDerivedKey')
const kdfSetup = require('../setup/kdf').kdf

/**
 * Derive a key from multiple factors of input
 *
 * @example
 * // setup 16 byte 2-of-3-factor multi-factor derived key with a password, HOTP code, and UUID recovery code
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.password('password'),
 *   await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
 *   await mfkdf.setup.factors.uuid({ id: 'recovery', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
 * ], {threshold: 2})
 *
 * // derive key using 2 of the 3 factors
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   password: mfkdf.derive.factors.password('password'),
 *   hotp: mfkdf.derive.factors.hotp(365287)
 * })
 *
 * setup.key.toString('hex') // -> 34…71
 * derive.key.toString('hex') // -> 34…71
 *
 * @param {Object} policy - The key policy for the key being derived
 * @param {Object.<string, MFKDFFactor>} factors - Factors used to derive this key
 * @param {Object} [options] - Configuration options
 * @param {number} [options.time=2] - Argon2id iterations to use (minimum 2)
 * @param {number} [options.memory=24576] - Argon2id memory to use (minimum 24576)
 * @returns {MFKDFDerivedKey} A multi-factor derived key object
 * @author Multifactor <support@multifactor.com>
 * @since 0.9.0
 * @async
 * @memberOf derive
 */
async function key (policy, factors, options) {
  const ajv = new Ajv()
  const valid = ajv.validate(policySchema, policy)
  if (!valid) throw new TypeError('invalid key policy: ' + ajv.errorsText())
  if (Object.keys(factors).length < policy.threshold) {
    throw new RangeError('insufficient factors provided to derive key')
  }

  const shares = []
  const newFactors = []
  const outputs = {}

  for (const factor of policy.factors) {
    if (factors[factor.id] && typeof factors[factor.id] === 'function') {
      const material = await factors[factor.id](factor.params)
      let share

      if (material.type === 'persisted') {
        share = material.data
      } else {
        if (material.type !== factor.type) {
          throw new TypeError(
            'wrong factor material function used for this factor type'
          )
        }

        const pad = Buffer.from(factor.pad, 'base64')
        let stretched = Buffer.from(
          await hkdf('sha256', material.data, factor.salt, '', 32)
        )
        if (Buffer.byteLength(pad) > 32) {
          stretched = Buffer.concat([
            Buffer.alloc(Buffer.byteLength(pad) - 32),
            stretched
          ])
        }

        share = xor(pad, stretched)
      }

      shares.push(share)
      if (material.output) outputs[factor.id] = await material.output()
      newFactors.push(material.params)
    } else {
      shares.push(null)
      newFactors.push(null)
    }
  }

  if (shares.filter((x) => Buffer.isBuffer(x)).length < policy.threshold) {
    throw new RangeError('insufficient factors provided to derive key')
  }

  // kdf
  const kdfSettings = kdfSetup({
    kdf: 'argon2id',
    argon2time: Math.max(2, options && options.time ? options.time : 2),
    argon2mem: Math.max(
      24576,
      options && options.memory ? options.memory : 24576
    )
  })

  const secret = combine(shares, policy.threshold, policy.factors.length)
  const key = await kdf(
    secret,
    Buffer.from(policy.salt, 'base64'),
    32,
    kdfSettings
  )

  const newPolicy = JSON.parse(JSON.stringify(policy))

  for (const [index, factor] of newFactors.entries()) {
    if (typeof factor === 'function') {
      newPolicy.factors[index].params = await factor({ key })
    }
  }

  const originalShares = recover(
    shares,
    policy.threshold,
    policy.factors.length
  )

  return new MFKDFDerivedKey(newPolicy, key, secret, originalShares, outputs)
}
module.exports.key = key

const { createHash } = require('crypto')

/**
 * Extracts the signable content from a policy object.
 *
 * @param {Object} [policy] - MFKDF policy object
 * @returns {Buffer} The extracted data
 * @author Multifactor <support@multifactor.com>
 * @since 2.0.0-alpha
 * @async
 */
async function extract (policy) {
  const hash = createHash('sha256')

  hash.update(JSON.stringify(policy.$id))
  hash.update(JSON.stringify(policy.threshold))
  hash.update(JSON.stringify(policy.salt))
  hash.update(JSON.stringify(policy.factors))

  return hash.digest()
}

module.exports.extract = extract

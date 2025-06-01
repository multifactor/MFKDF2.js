/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('kdf', () => {
  test('types', async () => {
    const pbkdf2 = await mfkdf.kdf(
      'password',
      'somesalt',
      16,
      mfkdf.setup.kdf({ kdf: 'pbkdf2' })
    )
    const bcrypt = await mfkdf.kdf(
      'password',
      'somesalt',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    const scrypt = await mfkdf.kdf(
      'password',
      'somesalt',
      16,
      mfkdf.setup.kdf({ kdf: 'scrypt' })
    )
    const argon2 = await mfkdf.kdf(
      'password',
      'somesalt',
      16,
      mfkdf.setup.kdf({ kdf: 'argon2id' })
    )
    const hkdf = await mfkdf.kdf(
      'password',
      'somesalt',
      16,
      mfkdf.setup.kdf({ kdf: 'hkdf' })
    )

    Buffer.isBuffer(pbkdf2).should.be.true
    Buffer.isBuffer(bcrypt).should.be.true
    Buffer.isBuffer(scrypt).should.be.true
    Buffer.isBuffer(argon2).should.be.true
    Buffer.isBuffer(hkdf).should.be.true
  })

  test('pbkdf2/sha1', async () => {
    const key = await mfkdf.kdf('password', 'salt', 16, {
      type: 'pbkdf2',
      params: {
        rounds: 25555,
        digest: 'sha1'
      }
    })
    Buffer.isBuffer(key).should.be.true
    key.toString('hex').should.equal('8ee4a527b20aa8feeb78d70447d84e20')
  })

  test('pbkdf2/sha512', async () => {
    const key = await mfkdf.kdf('secret', 'salt', 64, {
      type: 'pbkdf2',
      params: {
        rounds: 100000,
        digest: 'sha512'
      }
    })
    key
      .toString('hex')
      .should.equal(
        '3745e482c6e0ade35da10139e797157f4a5da669dad7d5da88ef87e47471cc47ed941c7ad618e827304f083f8707f12b7cfdd5f489b782f10cc269e3c08d59ae'
      )
  })

  test('pbkdf2/default', async () => {
    const key1 = await mfkdf.kdf(
      'test',
      '',
      32,
      mfkdf.setup.kdf({ kdf: 'pbkdf2' })
    )
    const key2 = await mfkdf.kdf('test', '', 32, {
      type: 'pbkdf2',
      params: {
        rounds: 310000,
        digest: 'sha256'
      }
    })
    key1.toString('hex').should.equal(key2.toString('hex'))
  })

  test('bcrypt/same', async () => {
    const key1 = await mfkdf.kdf(
      'password1',
      'salt1',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    const key2 = await mfkdf.kdf(
      'password1',
      'salt1',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    key1.toString('hex').should.equal(key2.toString('hex'))
  })

  test('bcrypt/inputdiff', async () => {
    const key1 = await mfkdf.kdf(
      'password1',
      'salt1',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    const key2 = await mfkdf.kdf(
      'password2',
      'salt1',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    key1.should.not.equal(key2)
  })

  test('bcrypt/saltdiff', async () => {
    const key1 = await mfkdf.kdf(
      'password1',
      'salt1',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    const key2 = await mfkdf.kdf(
      'password1',
      'salt2',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    key1.should.not.equal(key2)
  })

  test('bcrypt/rounddiff', async () => {
    const key1 = await mfkdf.kdf('password1', 'salt1', 16, {
      type: 'bcrypt',
      params: { rounds: 10 }
    })
    const key2 = await mfkdf.kdf('password1', 'salt2', 16, {
      type: 'bcrypt',
      params: { rounds: 11 }
    })
    key1.should.not.equal(key2)
  })

  test('bcrypt/length', async () => {
    const key16 = await mfkdf.kdf(
      'password',
      'salt',
      16,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    Buffer.byteLength(key16).should.equal(16)

    const key32 = await mfkdf.kdf(
      'password',
      'salt',
      32,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    Buffer.byteLength(key32).should.equal(32)

    const key64 = await mfkdf.kdf(
      'password',
      'salt',
      64,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    Buffer.byteLength(key64).should.equal(64)
  })

  test('bcrypt/known', async () => {
    const key = await mfkdf.kdf(
      'password',
      'salt',
      32,
      mfkdf.setup.kdf({ kdf: 'bcrypt' })
    )
    key
      .toString('hex')
      .should.equal(
        'cb36d3d02d502acdf10dfc2d022bf3c024f16a368ba2df4456fbf97291f64334'
      )
  })

  test('scrypt/fast', async () => {
    const key = await mfkdf.kdf(
      'password',
      'salt',
      64,
      mfkdf.setup.kdf({
        kdf: 'scrypt',
        scryptcost: 16384,
        scryptblocksize: 8,
        scryptparallelism: 1
      })
    )
    key
      .toString('hex')
      .should.equal(
        '745731af4484f323968969eda289aeee005b5903ac561e64a5aca121797bf7734ef9fd58422e2e22183bcacba9ec87ba0c83b7a2e788f03ce0da06463433cda6'
      )
  })

  test('scrypt/defaults', async () => {
    const key = await mfkdf.kdf(
      'secure',
      'secure',
      32,
      mfkdf.setup.kdf({ kdf: 'scrypt' })
    )
    key
      .toString('hex')
      .should.equal(
        '9009fca57ef2b8c342bdad6b9247e4a1b5bd85628152116513ad44e93cf1b0e2'
      )
  })

  test('scrypt/N', async () => {
    const key = await mfkdf.kdf(
      'secure',
      'secure',
      32,
      mfkdf.setup.kdf({ kdf: 'scrypt', scryptcost: 1024 })
    )
    key
      .toString('hex')
      .should.equal(
        'ceb6a6bf4f4afeb3d1806714474d4f00ca97c2ad76a641269192d11444e13a6b'
      )
  })

  test('scrypt/R', async () => {
    const key = await mfkdf.kdf(
      'secure',
      'secure',
      32,
      mfkdf.setup.kdf({ kdf: 'scrypt', scryptcost: 1024, scryptblocksize: 16 })
    )
    key
      .toString('hex')
      .should.equal(
        'a63de1de715f95bebd9f6d58d78ff11028a8412c1fcf71673544373c67095836'
      )
  })

  test('scrypt/P', async () => {
    const key = await mfkdf.kdf(
      'secure',
      'secure',
      32,
      mfkdf.setup.kdf({ kdf: 'scrypt', scryptcost: 1024, scryptparallelism: 2 })
    )
    key
      .toString('hex')
      .should.equal(
        'ef224277727457992dc05983b1fd1208bae35b100c853ba4bb11f1ba7ca4c436'
      )
  })

  test('argon2i', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ kdf: 'argon2i' })
    )
    key
      .toString('hex')
      .should.equal(
        '7357892df510f136a0688ceab37bbaf7ba695de590065072717fa6728961c92a'
      )
  })

  test('argon2d', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ kdf: 'argon2d' })
    )
    key
      .toString('hex')
      .should.equal(
        '423b0dcc7bbfe16fa8ee7a2e2ebd8891873d726f9dfe70890a7197a5503a2848'
      )
  })

  test('argon2id', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ kdf: 'argon2id' })
    )
    key
      .toString('hex')
      .should.equal(
        '5cddd5b69d1fe5d83bc3e04e9122f05d9b2128a194cb739baf74679875c4b3a1'
      )
  })

  test('argon2id/mem', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ type: 'argon2id', argon2mem: 16384 })
    )
    key
      .toString('hex')
      .should.equal(
        'e043f979311b14ff8378b785469974e899a08f05509323a04b2ca29ef63ff3af'
      )
  })

  test('argon2id/time', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ type: 'argon2id', argon2time: 1 })
    )
    key
      .toString('hex')
      .should.equal(
        'bf6b1773bdae362ecea04b889079b6628d1f35d96a2be9f2a5481c2d1236e8d7'
      )
  })

  test('argon2id/parallelism', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ type: 'argon2id', argon2parallelism: 2 })
    )
    key
      .toString('hex')
      .should.equal(
        '5c12c6873b938cd8467b677d23e525389e3ff7ed62b4ad9e285e1191244f40ca'
      )
  })

  test('default', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({})
    )
    key
      .toString('hex')
      .should.equal(
        '5cddd5b69d1fe5d83bc3e04e9122f05d9b2128a194cb739baf74679875c4b3a1'
      )
  })

  test('invalid', async () => {
    await mfkdf
      .kdf('password1', 'salt1', 16, { type: 'invalid', params: {} })
      .should.be.rejectedWith(RangeError)
  })
})

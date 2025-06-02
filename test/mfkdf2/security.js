/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const crypto = require('crypto')
const { hkdf } = require('@panva/hkdf')
const xor = require('buffer-xor')

suite('mfkdf2/security', () => {
  suite('factor-fungibility', () => {
    test('correct', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        )
      )

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('incorrect', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        )
      )

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password2'),
        password2: mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.not.equal(setup.key.toString('hex'))
    })
  })

  suite('share-indistinguishability', () => {
    test('share-size', async () => {
      const secret = crypto.randomBytes(32)

      const shares1 = mfkdf.secrets.share(secret, 1, 3)
      shares1.should.have.length(3)
      for (const share of shares1) {
        share.should.have.length(32)
      }
      mfkdf.secrets
        .combine(shares1.slice(0, 1).concat([null, null]), 1, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))
      mfkdf.secrets
        .combine([null, null].concat(shares1.slice(2, 3)), 1, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))

      const shares2 = mfkdf.secrets.share(secret, 2, 3)
      shares2.should.have.length(3)
      for (const share of shares2) {
        share.should.have.length(32)
      }
      mfkdf.secrets
        .combine(shares2.slice(0, 2).concat([null]), 2, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))
      mfkdf.secrets
        .combine([null].concat(shares2.slice(1, 3)), 2, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))

      const shares3 = mfkdf.secrets.share(secret, 3, 3)
      shares3.should.have.length(3)
      for (const share of shares3) {
        share.should.have.length(32)
      }
      mfkdf.secrets
        .combine(shares3.slice(0, 3), 3, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))
    })
  })

  suite('share-encryption', () => {
    test('correct', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const materialp1 = await mfkdf.derive.factors.password('password1')(
        setup.policy.factors[0].params
      )
      const padp1 = Buffer.from(setup.policy.factors[0].pad, 'base64')
      const stretchedp1 = Buffer.from(
        await hkdf(
          'sha256',
          materialp1.data,
          setup.policy.factors[0].salt,
          '',
          32
        )
      )
      const sharep1 = xor(padp1, stretchedp1)

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      await derive.recoverFactor(
        await mfkdf.setup.factors.password('newPassword1', { id: 'password1' })
      )
      const derive2f = await mfkdf.policy.derive(derive.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive2f.key.toString('hex').should.not.equal(setup.key.toString('hex'))
      const derive2 = await mfkdf.policy.derive(derive.policy, {
        password1: mfkdf.derive.factors.password('newPassword1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive2.key.toString('hex').should.equal(setup.key.toString('hex'))

      const materialp3 = await mfkdf.derive.factors.password('newPassword1')(
        derive.policy.factors[0].params
      )
      const padp3 = Buffer.from(derive.policy.factors[0].pad, 'base64')
      const stretchedp3 = Buffer.from(
        await hkdf(
          'sha256',
          materialp3.data,
          derive.policy.factors[0].salt,
          '',
          32
        )
      )
      const sharep3 = xor(padp3, stretchedp3)

      await derive2.recoverFactor(
        await mfkdf.setup.factors.password('newPassword2', { id: 'password1' })
      )
      const derive3 = await mfkdf.policy.derive(derive2.policy, {
        password1: mfkdf.derive.factors.password('newPassword2'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive3.key.toString('hex').should.equal(setup.key.toString('hex'))

      sharep1.should.not.equal(sharep3)
    })
  })

  suite('factor-secret-encryption', () => {
    test('hotp', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hotp({
          secret: Buffer.from('hello world')
        })
      ])

      const recover = xor(
        Buffer.from(setup.policy.factors[0].params.pad, 'base64'),
        Buffer.from('hello world')
      ).toString('hex')
      const key = setup.key.toString('hex').slice(0, recover.length)
      recover.should.not.equal(key)

      const derive1 = await mfkdf.derive.key(setup.policy, {
        hotp: mfkdf.derive.factors.hotp(365287)
      })

      setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
    })
  })

  test('totp', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp({
        secret: Buffer.from('hello world'),
        time: 1650430806597
      })
    ])

    const recover = xor(
      Buffer.from(setup.policy.factors[0].params.pad, 'base64'),
      Buffer.from('hello world')
    ).toString('hex')
    const key = setup.key.toString('hex').slice(0, recover.length)
    recover.should.not.equal(key)

    const derive1 = await mfkdf.derive.key(setup.policy, {
      totp: mfkdf.derive.factors.totp(528258, { time: 1650430943604 })
    })

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
  })
})

/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('mfkdf2/changes', () => {
  suite('key-size-256', () => {
    test('default', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { kdf: 'hkdf' }
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
      setup.key.length.should.equal(32)
      derive.key.length.should.equal(32)
    })

    test('override', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { kdf: 'hkdf' }
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
      setup.key.length.should.equal(32)
      derive.key.length.should.equal(32)
    })
  })

  suite('kdf-argon2id', () => {
    test('default', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { kdf: 'hkdf' }
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
      setup.key.length.should.equal(32)
      derive.key.length.should.equal(32)
    })

    test('override/mismatch/time', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { time: 3 }
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.not.equal(setup.key.toString('hex'))
    })

    test('override/mismatch/memory', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { memory: 65536 }
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.key.toString('hex').should.not.equal(setup.key.toString('hex'))
    })

    test('override/matching', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { memory: 65536, time: 3 }
      )

      const derive = await mfkdf.derive.key(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password1')
        },
        { memory: 65536, time: 3 }
      )

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })
  })
})

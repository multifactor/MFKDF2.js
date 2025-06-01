/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

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
})

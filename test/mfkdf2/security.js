/* eslint no-unused-expressions: "off" */
const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
chai.should();

const mfkdf = require("../../src");
const { suite, test } = require("mocha");
const crypto = require("crypto");

suite("mfkdf2/security", () => {
  suite("factor-fungibility", () => {
    test("correct", async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password("password1", { id: "password1" }),
          await mfkdf.setup.factors.password("password2", { id: "password2" })
        )
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password("password1"),
        password2: mfkdf.derive.factors.password("password2"),
      });

      derive.key.toString("hex").should.equal(setup.key.toString("hex"));
    });

    test("incorrect", async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password("password1", { id: "password1" }),
          await mfkdf.setup.factors.password("password2", { id: "password2" })
        )
      );

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password("password2"),
        password2: mfkdf.derive.factors.password("password1"),
      });

      derive.key.toString("hex").should.not.equal(setup.key.toString("hex"));
    });
  });

  suite("share-indistinguishability", () => {
    test("share-size", async () => {
      const secret = crypto.randomBytes(32);

      const shares1 = await mfkdf.secrets.share(secret, 1, 3);
      shares1.should.have.length(3);
      for (const share of shares1) {
        share.should.have.length(32);
      }
      mfkdf.secrets
        .combine(shares1.slice(0, 1).concat([null, null]), 1, 3)
        .toString("hex")
        .should.equal(secret.toString("hex"));
      mfkdf.secrets
        .combine([null, null].concat(shares1.slice(2, 3)), 1, 3)
        .toString("hex")
        .should.equal(secret.toString("hex"));

      const shares2 = await mfkdf.secrets.share(secret, 2, 3);
      shares2.should.have.length(3);
      for (const share of shares2) {
        share.should.have.length(32);
      }
      mfkdf.secrets
        .combine(shares2.slice(0, 2).concat([null]), 2, 3)
        .toString("hex")
        .should.equal(secret.toString("hex"));
      mfkdf.secrets
        .combine([null].concat(shares2.slice(1, 3)), 2, 3)
        .toString("hex")
        .should.equal(secret.toString("hex"));

      const shares3 = await mfkdf.secrets.share(secret, 3, 3);
      shares3.should.have.length(3);
      for (const share of shares3) {
        share.should.have.length(32);
      }
      mfkdf.secrets
        .combine(shares3.slice(0, 3), 3, 3)
        .toString("hex")
        .should.equal(secret.toString("hex"));
    });
  });
});

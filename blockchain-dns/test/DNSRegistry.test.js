const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("DNSRegistry", function () {
  let registry, owner, attacker, newOwner;

  beforeEach(async function () {
    [owner, attacker, newOwner] = await ethers.getSigners();
    const DNSRegistry = await ethers.getContractFactory("DNSRegistry");
    registry = await DNSRegistry.deploy();
    await registry.waitForDeployment();
  });

  // ── Registration ────────────────────────────────────────────────────

  describe("Domain Registration", function () {
    it("should register a new domain", async function () {
      await registry.registerDomain("test.chain", "1.2.3.4", 300);
      const [ip, domOwner] = await registry.resolveDomain("test.chain");
      expect(ip).to.equal("1.2.3.4");
      expect(domOwner).to.equal(owner.address);
    });

    it("should reject duplicate registration", async function () {
      await registry.registerDomain("test.chain", "1.2.3.4", 300);
      await expect(
        registry.connect(attacker).registerDomain("test.chain", "5.6.7.8", 300)
      ).to.be.revertedWith("Domain already registered");
    });

    it("should reject empty name", async function () {
      await expect(
        registry.registerDomain("", "1.2.3.4", 300)
      ).to.be.revertedWith("Empty name");
    });

    it("should reject TTL below minimum", async function () {
      await expect(
        registry.registerDomain("test.chain", "1.2.3.4", 10)
      ).to.be.revertedWith("TTL too low");
    });

    it("should report availability correctly", async function () {
      expect(await registry.isAvailable("test.chain")).to.be.true;
      await registry.registerDomain("test.chain", "1.2.3.4", 300);
      expect(await registry.isAvailable("test.chain")).to.be.false;
    });
  });

  // ── Anti-Spoofing ──────────────────────────────────────────────────

  describe("Anti-Spoofing / Anti-Hijack", function () {
    beforeEach(async function () {
      await registry.registerDomain("secure.chain", "10.0.0.1", 300);
    });

    it("should prevent unauthorized record updates (spoofing)", async function () {
      await expect(
        registry.connect(attacker).updateRecord("secure.chain", 0, "6.6.6.6", 300)
      ).to.be.revertedWith("Not domain owner");

      // Verify record is unchanged
      const [ip] = await registry.resolveDomain("secure.chain");
      expect(ip).to.equal("10.0.0.1");
    });

    it("should prevent unauthorized ownership transfer (hijacking)", async function () {
      await expect(
        registry.connect(attacker).transferOwnership("secure.chain", attacker.address)
      ).to.be.revertedWith("Not domain owner");

      const [, domOwner] = await registry.resolveDomain("secure.chain");
      expect(domOwner).to.equal(owner.address);
    });

    it("should prevent unauthorized record addition", async function () {
      await expect(
        registry.connect(attacker).addRecord("secure.chain", 0, "evil.ip", 300)
      ).to.be.revertedWith("Not domain owner");
    });

    it("should prevent unauthorized record deletion", async function () {
      await expect(
        registry.connect(attacker).deleteRecord("secure.chain", 0)
      ).to.be.revertedWith("Not domain owner");
    });
  });

  // ── Record Management ──────────────────────────────────────────────

  describe("Record Management", function () {
    beforeEach(async function () {
      await registry.registerDomain("multi.chain", "1.1.1.1", 300);
    });

    it("should add multiple record types", async function () {
      await registry.addRecord("multi.chain", 1, "::1", 300);              // AAAA
      await registry.addRecord("multi.chain", 2, "www.multi.chain", 300);  // CNAME
      await registry.addRecord("multi.chain", 3, "v=spf1 ~all", 600);     // TXT

      const info = await registry.getDomainInfo("multi.chain");
      expect(info.recordCount).to.equal(4); // 1 initial A + 3 added
    });

    it("should update a record", async function () {
      await registry.updateRecord("multi.chain", 0, "2.2.2.2", 600);
      const [ip] = await registry.resolveDomain("multi.chain");
      expect(ip).to.equal("2.2.2.2");
    });

    it("should delete a record", async function () {
      await registry.addRecord("multi.chain", 3, "some-txt", 300);
      await registry.deleteRecord("multi.chain", 1);
      const info = await registry.getDomainInfo("multi.chain");
      expect(info.recordCount).to.equal(1);
    });

    it("should get all records", async function () {
      await registry.addRecord("multi.chain", 3, "hello=world", 120);
      const [values, types, ttls] = await registry.getAllRecords("multi.chain");
      expect(values.length).to.equal(2);
      expect(values[0]).to.equal("1.1.1.1");
      expect(values[1]).to.equal("hello=world");
    });
  });

  // ── Ownership Transfer ─────────────────────────────────────────────

  describe("Ownership Transfer", function () {
    it("should transfer domain to new owner", async function () {
      await registry.registerDomain("xfer.chain", "1.2.3.4", 300);
      await registry.transferOwnership("xfer.chain", newOwner.address);

      const info = await registry.getDomainInfo("xfer.chain");
      expect(info.owner).to.equal(newOwner.address);

      // Old owner can no longer update
      await expect(
        registry.updateRecord("xfer.chain", 0, "9.9.9.9", 300)
      ).to.be.revertedWith("Not domain owner");

      // New owner can
      await registry.connect(newOwner).updateRecord("xfer.chain", 0, "9.9.9.9", 300);
      const [ip] = await registry.resolveDomain("xfer.chain");
      expect(ip).to.equal("9.9.9.9");
    });
  });

  // ── Domain Lifecycle ───────────────────────────────────────────────

  describe("Renewal & Expiry", function () {
    it("should renew a domain", async function () {
      await registry.registerDomain("renew.chain", "1.1.1.1", 300);
      const infoBefore = await registry.getDomainInfo("renew.chain");
      await registry.renewDomain("renew.chain");
      const infoAfter = await registry.getDomainInfo("renew.chain");
      expect(infoAfter.expiresAt).to.be.greaterThan(infoBefore.expiresAt);
    });
  });

  // ── Enumeration ────────────────────────────────────────────────────

  describe("Enumeration", function () {
    it("should track domain count", async function () {
      await registry.registerDomain("a.chain", "1.0.0.1", 60);
      await registry.registerDomain("b.chain", "1.0.0.2", 60);
      await registry.registerDomain("c.chain", "1.0.0.3", 60);
      expect(await registry.getDomainCount()).to.equal(3);
    });
  });
});

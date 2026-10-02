/**
 * Deploy DNSRegistry to a local or test network.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js --network localhost
 *   npx hardhat run scripts/deploy.js --network sepolia
 */

const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║       Blockchain DNS — Contract Deployment       ║");
  console.log("╚══════════════════════════════════════════════════╝");
  console.log(`  Deployer : ${deployer.address}`);
  console.log(`  Balance  : ${hre.ethers.formatEther(await hre.ethers.provider.getBalance(deployer.address))} ETH`);
  console.log(`  Network  : ${hre.network.name}`);
  console.log();

  // Deploy
  const DNSRegistry = await hre.ethers.getContractFactory("DNSRegistry");
  const registry = await DNSRegistry.deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();

  console.log(`  ✓ DNSRegistry deployed at: ${address}`);
  console.log();

  // Register sample domains for demo
  console.log("  Registering sample domains…");

  const samples = [
    { name: "example.chain",  ip: "93.184.216.34",  ttl: 300 },
    { name: "secure.chain",   ip: "104.21.32.1",    ttl: 600 },
    { name: "mysite.chain",   ip: "192.168.1.100",  ttl: 120 },
    { name: "blockdns.chain", ip: "10.0.0.42",      ttl: 300 },
  ];

  for (const { name, ip, ttl } of samples) {
    const tx = await registry.registerDomain(name, ip, ttl);
    await tx.wait();
    console.log(`    ✓ ${name.padEnd(20)} → ${ip}`);
  }

  // Add extra records to example.chain
  console.log("\n  Adding extra records to example.chain…");
  let tx = await registry.addRecord("example.chain", 4, "v=spf1 include:_spf.google.com ~all", 3600); // TXT
  await tx.wait();
  console.log("    ✓ TXT record added");

  tx = await registry.addRecord("example.chain", 3, "www.example.chain", 300); // CNAME
  await tx.wait();
  console.log("    ✓ CNAME record added");

  console.log("\n  ════════════════════════════════════════════════");
  console.log(`  Contract address: ${address}`);
  console.log("  Save this address for the resolver and frontend.");
  console.log("  ════════════════════════════════════════════════\n");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

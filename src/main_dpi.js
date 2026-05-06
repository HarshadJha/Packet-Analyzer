#!/usr/bin/env node
import { DPIEngine } from './dpi_engine.js';
import { AppType } from './types.js';

function printUsage() {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                DPI ENGINE v1.0 (JS)                          ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: node src/main_dpi.js <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file
  output.pcap    Output PCAP file

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --rules <file>         Load blocking rules from file
  --verbose              Enable verbose output
`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    printUsage();
    process.exit(1);
  }

  const inputFile = args[0];
  const outputFile = args[1];

  const config = {
    numLoadBalancers: 1, // Single threaded for JS port simplicity
    fpsPerLb: 1,
    rulesFile: ''
  };

  const engine = new DPIEngine(config);
  
  // Basic option parsing
  for (let i = 2; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--block-ip' && i + 1 < args.length) {
      engine.ruleManager.blockIP(args[++i]);
    } else if (arg === '--block-app' && i + 1 < args.length) {
      const appName = args[++i].toUpperCase();
      if (AppType[appName] !== undefined) {
        engine.ruleManager.blockApp(AppType[appName]);
      } else {
        console.warn(`Unknown app: ${appName}`);
      }
    } else if (arg === '--block-domain' && i + 1 < args.length) {
      engine.ruleManager.blockDomain(args[++i]);
    } else if (arg === '--rules' && i + 1 < args.length) {
      config.rulesFile = args[++i];
    }
  }

  try {
    await engine.processFile(inputFile, outputFile);
  } catch (err) {
    console.error(`Error during processing: ${err.message}`);
    process.exit(1);
  }
}

main();

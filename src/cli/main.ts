#!/usr/bin/env node

import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { PortScanner } from "../core/port-scanner.js";
import type { IScanResult } from "../shared/types.js";

function formatScanResult(result: IScanResult): void {
  console.log(`\n${"=".repeat(70)}`);
  console.log(`PORT SCAN RESULTS`);
  console.log(`${"=".repeat(70)}`);
  console.log(`Host: ${result.host} (${result.ip})`);
  console.log(`Scan Time: ${(result.scanTime / 1000).toFixed(2)}s`);
  console.log(`Ports Scanned: ${result.totalPortsScanned}`);
  console.log(`Open Ports: ${result.openPorts.length}`);

  console.log(
    `\nVulnerabilities:` +
    ` Critical: ${result.summary.critical},` +
    ` High: ${result.summary.high},` +
    ` Medium: ${result.summary.medium},` +
    ` Low: ${result.summary.low}`
  );

  if (result.openPorts.length === 0) {
    console.log(`\nNo open ports found.`);
    return;
  }

  console.log(`\n${"─".repeat(70)}`);
  console.log(`OPEN PORTS`);
  console.log(`${"─".repeat(70)}\n`);

  for (const port of result.openPorts) {
    console.log(`Port ${port.port} - ${port.info.service} (${port.info.category})`);
    console.log(`  State: ${port.state}`);
    console.log(`  Response Time: ${port.responseTime.toFixed(3)}ms`);

    if (port.behavior) {
      console.log(`  Behavior: ${port.behavior}`);
    }

    if (port.inference) {
      console.log(`  Inference: ${port.inference}`);
    }

    if (port.stability) {
      console.log(`  Stability: ${port.stability}`);
    }

    if (port.fingerprint?.identified) {
      console.log(`  Service: ${port.fingerprint.service}`);
      if (port.fingerprint.version) {
        console.log(`  Version: ${port.fingerprint.version}`);
      }
    }

    if (port.vulnerabilities.length > 0) {
      console.log(`  Vulnerabilities:`);
      for (const vuln of port.vulnerabilities) {
        console.log(`    [${vuln.severity}] ${vuln.title}`);
        console.log(`      ${vuln.description}`);
        console.log(`      → ${vuln.recommendation}`);
      }
    }

    console.log();
  }

  console.log(`${"=".repeat(70)}\n`);
}

async function main() {
  const argv = yargs(hideBin(process.argv))
    .command("$0 <host>", "Scan a host for open ports", (yargs) => {
      yargs.positional("host", {
        describe: "Target hostname or IP address",
        type: "string",
        demandOption: true,
      });
    })
    .option("quick", {
      alias: "q",
      type: "boolean",
      description: "Quick scan (common ports only)",
      default: false,
    })
    .option("range", {
      alias: "r",
      type: "string",
      description: "Port range (e.g., 1-1000)",
    })
    .option("timeout", {
      alias: "t",
      type: "number",
      description: "Connection timeout in ms",
      default: 1000,
    })
    .option("concurrency", {
      alias: "c",
      type: "number",
      description: "Maximum concurrent connections",
      default: 200,
    })
    .option("fingerprint", {
      type: "boolean",
      description: "Enable service fingerprinting",
      default: true,
    })
    .option("vuln-check", {
      type: "boolean",
      description: "Enable vulnerability checks",
      default: true,
    })
    .option("json", {
      alias: "j",
      type: "boolean",
      description: "Output results as JSON",
      default: false,
    })
    .example("$0 example.com", "Full port scan")
    .example("$0 example.com --quick", "Quick scan (common ports)")
    .example("$0 example.com --range 1-1000", "Scan ports 1-1000")
    .example("$0 example.com --fingerprint=false", "Disable service fingerprinting")
    .example("$0 example.com --vuln-check=false", "Disable vulnerability checks")
    .example("$0 example.com --json", "Output as JSON")
    .strict()
    .parseSync();

  const host = argv["host"] as string;

  console.log(`Starting port scan on ${host}...`);

  const scanner = new PortScanner({
    connectTimeout: argv.timeout,
    maxConcurrency: argv.concurrency,
    enableFingerprinting: argv.fingerprint,
    enableVulnerabilityChecks: argv.vulnCheck,
  });

  try {
    const result: IScanResult = await (async () => {
      if (argv.quick) {
        return scanner.quickScan(host);
      } else if (argv.range) {
        const [start, end] = argv.range.split("-").map(Number);
        if (!start || !end || start > end) {
          console.error("Invalid port range. Use format: 1-1000");
          process.exit(1);
        }
        return scanner.scanRange(host, start, end);
      } else {
        return scanner.scan(host);
      }
    })();

    if (argv.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      formatScanResult(result);
    }

  } catch (error: unknown) {
    if (error instanceof Error) {
      console.error(`\nScan failed: ${error.message}`);
    } else {
      console.error("\nScan failed:", error);
    }
    process.exit(1);
  }
}

main();
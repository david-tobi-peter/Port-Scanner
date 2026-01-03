import dns from "node:dns/promises";
import { PortProber } from "./port-prober.js";
import { ServiceFingerprinter } from "./service-finger-printer.js";
import { VulnerabilityAnalyzer } from "./vulnerability-analyzer.js";
import { measureTime, getElapsedTime } from "../shared/utils.js";
import type { IProbeResult, IScanOptions, IScanResult } from "../shared/types.js";
import { DEFAULT_SCAN_OPTIONS } from "../shared/constants.js";

export class PortScanner {
  private prober: PortProber;
  private fingerprinter: ServiceFingerprinter;
  private vulnAnalyzer: VulnerabilityAnalyzer;
  private options: Required<IScanOptions>;

  constructor(options: IScanOptions = {}) {
    this.options = { ...DEFAULT_SCAN_OPTIONS, ...options };
    this.prober = new PortProber(this.options);
    this.fingerprinter = new ServiceFingerprinter();
    this.vulnAnalyzer = new VulnerabilityAnalyzer();
  }

  async scan(host: string): Promise<IScanResult> {
    const scanStartTime = process.hrtime.bigint();

    const { result: address } = await measureTime(async () => {
      const lookup = await dns.lookup(host);
      return lookup.address;
    });

    const openPorts = await this.scanPorts(address);

    const allVulns = openPorts.flatMap(p => p.vulnerabilities);
    const summary = {
      critical: allVulns.filter(v => v.severity === "CRITICAL").length,
      high: allVulns.filter(v => v.severity === "HIGH").length,
      medium: allVulns.filter(v => v.severity === "MEDIUM").length,
      low: allVulns.filter(v => v.severity === "LOW").length,
    };

    return {
      host,
      ip: address,
      openPorts: openPorts.sort((a, b) => a.port - b.port),
      totalPortsScanned: this.options.portRange.end - this.options.portRange.start + 1,
      scanTime: getElapsedTime(scanStartTime),
      summary,
    };
  }

  async scanRange(host: string, startPort: number, endPort: number): Promise<IScanResult> {
    const prevRange = this.options.portRange;
    this.options.portRange = { start: startPort, end: endPort };

    try {
      return await this.scan(host);
    } finally {
      this.options.portRange = prevRange;
    }
  }

  async quickScan(host: string): Promise<IScanResult> {
    const commonPorts = [
      21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
      443, 445, 993, 995, 1433, 3306, 3389, 5432,
      5900, 6379, 8080, 8443, 27017,
    ];

    const scanStartTime = process.hrtime.bigint();
    const { address } = await dns.lookup(host);

    const results = await Promise.all(
      commonPorts.map(port => this.prober.probe(address, port))
    );

    const openPorts: IProbeResult[] = [];

    for (const res of results) {
      if (res.state === "OPEN") {
        res.stability = await this.prober.assessStability(address, res.port);

        if (this.options.enableFingerprinting) {
          res.fingerprint = await this.fingerprinter.fingerprint(address, res.port, res.fingerprint?.banner);
        }

        if (this.options.enableVulnerabilityChecks) {
          res.vulnerabilities = this.vulnAnalyzer.analyze(res);
        }

        openPorts.push(res);
      }
    }

    const allVulns = openPorts.flatMap(p => p.vulnerabilities);
    const summary = {
      critical: allVulns.filter(v => v.severity === "CRITICAL").length,
      high: allVulns.filter(v => v.severity === "HIGH").length,
      medium: allVulns.filter(v => v.severity === "MEDIUM").length,
      low: allVulns.filter(v => v.severity === "LOW").length,
    };

    return {
      host,
      ip: address,
      openPorts: openPorts.sort((a, b) => a.port - b.port),
      totalPortsScanned: commonPorts.length,
      scanTime: getElapsedTime(scanStartTime),
      summary,
    };
  }

  private async scanPorts(ip: string): Promise<IProbeResult[]> {
    const openPorts: IProbeResult[] = [];
    let active = 0;
    let port = this.options.portRange.start;
    const endPort = this.options.portRange.end;

    await new Promise<void>((resolve) => {
      const next = () => {
        while (active < this.options.maxConcurrency && port <= endPort) {
          const p = port++;
          active++;

          this.prober.probeWithStability(ip, p).then(async (res) => {
            if (res.state === "OPEN") {
              if (this.options.enableFingerprinting) {
                res.fingerprint = await this.fingerprinter.fingerprint(ip, res.port, res.fingerprint?.banner);
              }

              if (this.options.enableVulnerabilityChecks) {
                res.vulnerabilities = this.vulnAnalyzer.analyze(res);
              }

              openPorts.push(res);
            }

            active--;
            if (port > endPort && active === 0) resolve();
            else next();
          });
        }
      };
      next();
    });

    return openPorts;
  }
}
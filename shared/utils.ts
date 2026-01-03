import { WELL_KNOWN_PORTS } from "./constants.js";
import type { IPortInfo, IVulnerability } from "./types.js";

export function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function getPortInfo(port: number, banner?: string): IPortInfo {
  const info = WELL_KNOWN_PORTS[port];

  if (!info) {
    return {
      service: "Unknown",
      category: "unknown",
      description: "Unregistered or custom service",
    };
  }

  if (banner) {
    const refined = refineBanner(port, banner);
    if (refined) return refined;
  }

  return info;
}

function refineBanner(port: number, banner: string): IPortInfo | null {
  const lower = banner.toLowerCase();

  if (port === 3000) {
    if (lower.includes("grafana")) {
      return { service: "Grafana", category: "monitoring", description: "Grafana Dashboard" };
    }
    if (lower.includes("node") || lower.includes("express")) {
      return { service: "Node.js", category: "web-framework", description: "Node.js application" };
    }
  }

  if (port === 8080) {
    if (lower.includes("tomcat")) {
      return { service: "Tomcat", category: "web", description: "Apache Tomcat" };
    }
    if (lower.includes("jenkins")) {
      return { service: "Jenkins", category: "web-framework", description: "Jenkins CI/CD" };
    }
  }

  if (port === 5000) {
    if (lower.includes("flask") || lower.includes("werkzeug")) {
      return { service: "Flask", category: "web-framework", description: "Flask application" };
    }
    if (lower.includes("docker") || lower.includes("registry")) {
      return { service: "Docker Registry", category: "container", description: "Docker Registry API" };
    }
  }

  return null;
}

export function calculateRiskScore(vulnerabilities: IVulnerability[]): number {
  const weights = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 };
  const score = vulnerabilities.reduce((sum, v) => sum + weights[v.severity], 0);
  return Math.min(score, 100);
}

export async function measureTime<T>(fn: () => Promise<T>): Promise<{ result: T; timeMs: number }> {
  const start = process.hrtime.bigint();
  const result = await fn();
  const end = process.hrtime.bigint();
  return { result, timeMs: Number(end - start) / 1_000_000 };
}

export function measureTimeSync<T>(fn: () => T): { result: T; timeMs: number } {
  const start = process.hrtime.bigint();
  const result = fn();
  const end = process.hrtime.bigint();
  return { result, timeMs: Number(end - start) / 1_000_000 };
}

export function getElapsedTime(startTime: bigint): number {
  return Number(process.hrtime.bigint() - startTime) / 1_000_000;
}
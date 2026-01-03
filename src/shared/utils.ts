import { WELL_KNOWN_PORTS } from "./constants.js";
import type { IPortInfo } from "./types.js";

export function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function getPortInfo(port: number): IPortInfo {
  const info = WELL_KNOWN_PORTS[port];

  if (!info) {
    return {
      service: "Unknown",
      category: "unknown",
      description: "Unregistered or custom service",
    };
  }

  return info;
}

export async function measureTime<T>(fn: () => Promise<T>): Promise<{ result: T; timeMs: number }> {
  const start = process.hrtime.bigint();
  const result = await fn();
  const end = process.hrtime.bigint();
  return { result, timeMs: Number(end - start) / 1_000_000 };
}

export function getElapsedTime(startTime: bigint): number {
  return Number(process.hrtime.bigint() - startTime) / 1_000_000;
}
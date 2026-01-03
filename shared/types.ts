export type TimingMsType = number;
export type PortStateType = "OPEN" | "CLOSED" | "FILTERED";
export type PortBehaviorType = "idle" | "immediate_close" | "sent_data" | "timeout";
export type StabilityType = "STABLE" | "EPHEMERAL";
export type PortCategoryType = "web" | "remote" | "database" | "messaging" |
  "dev" | "email" | "network" | "container" | "web-framework" | "monitoring" | "unknown";
export type SeverityType = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface IPortInfo {
  service: string;
  category: PortCategoryType;
  description?: string;
}

export interface IVulnerability {
  severity: SeverityType;
  title: string;
  description: string;
  recommendation: string;
}

export interface IServiceFingerprint {
  identified: boolean;
  service?: string;
  version?: string;
  banner?: string;
  confidence: number;
}

export interface IProbeResult {
  port: number;
  state: PortStateType;
  info: IPortInfo;
  behavior?: PortBehaviorType;
  inference?: string;
  stability?: StabilityType;
  fingerprint?: IServiceFingerprint;
  vulnerabilities: IVulnerability[];
  responseTime: TimingMsType;
}

export interface IScanOptions {
  connectTimeout?: TimingMsType;
  idleObserve?: number;
  maxConcurrency?: number;
  stabilityRetries?: number;
  stabilityDelay?: number;
  enableFingerprinting?: boolean;
  enableVulnerabilityChecks?: boolean;
  portRange?: { start: number; end: number };
}

export interface IScanResult {
  host: string;
  ip: string;
  openPorts: IProbeResult[];
  totalPortsScanned: number;
  scanTime: TimingMsType;
  osInference?: string;
  riskScore: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}
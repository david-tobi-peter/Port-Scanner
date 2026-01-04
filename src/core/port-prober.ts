import net from "net";
import { getPortInfo, delay, getElapsedTime } from "../shared/utils.js";
import type { IProbeResult, IScanOptions, PortStateType } from "../shared/types.js";
import { DEFAULT_SCAN_OPTIONS } from "../shared/constants.js";

export class PortProber {
  private options: Required<IScanOptions>;

  constructor(options: IScanOptions = {}) {
    this.options = { ...DEFAULT_SCAN_OPTIONS, ...options };
  }

  async probe(hostname: string, port: number): Promise<IProbeResult> {
    const socket = new net.Socket();
    const startTime = process.hrtime.bigint();

    let connected = false;
    let sawData = false;

    const result: IProbeResult = {
      hostname,
      port,
      state: "FILTERED" as PortStateType,
      info: getPortInfo(port),
      vulnerabilities: [],
      responseTime: 0,
      fingerprint: { identified: false }
    };

    return new Promise((resolve) => {
      socket.setTimeout(this.options.connectTimeout);

      socket.once("connect", () => {
        connected = true;
        result.state = "OPEN";
        result.responseTime = getElapsedTime(startTime);

        setTimeout(() => {
          if (!sawData) {
            result.behavior = "idle";
            result.inference = "Service accepts connection and waits for client input";
            socket.destroy();
          }
        }, this.options.idleObserve);
      });

      socket.on("data", (chunk) => {
        sawData = true;
        result.behavior = "sent_data";
        result.fingerprint.banner = chunk.toString("utf8", 0, Math.min(chunk.length, 512));
        socket.destroy();
      });

      socket.once("error", (err: any) => {
        result.responseTime = getElapsedTime(startTime);

        if (err.code === "ECONNREFUSED") {
          result.state = "CLOSED";
          result.inference = "Port is closed (connection actively refused)";
        } else if (err.code === "ETIMEDOUT" || err.code === "EHOSTUNREACH") {
          result.state = "FILTERED";
          result.inference = "Port is filtered (firewall/no route to host)";
        } else {
          result.state = "FILTERED";
          result.inference = `Error: ${err.code || err.message}`;
        }
        resolve(result);
      });

      socket.once("timeout", () => {
        result.responseTime = getElapsedTime(startTime);

        if (!connected) {
          result.state = "FILTERED";
          result.behavior = "timeout";
          result.inference = "Connection timed out (likely filtered by firewall)";
        }
        socket.destroy();
      });

      socket.once("close", () => {
        result.responseTime = getElapsedTime(startTime);

        if (connected && !sawData && !result.behavior) {
          result.behavior = "immediate_close";
          result.inference = "Service closes connection immediately (protocol enforcement or proxy)";
        }
        resolve(result);
      });

      socket.connect(port, hostname);
    });
  }

  async probeWithStability(hostname: string, port: number): Promise<IProbeResult> {
    const result = await this.probe(hostname, port);

    if (result.state === "OPEN") {
      for (let i = 0; i < this.options.stabilityRetries; i++) {
        await delay(this.options.stabilityDelay);
        const res = await this.probe(hostname, port);

        if (res.state !== "OPEN") {
          result.stability = "EPHEMERAL";
          result.inference = "Ephemeral/dynamic port (likely outbound connection, not service)";
          return result;
        }
      }

      result.stability = "STABLE";
    }

    return result;
  }
}
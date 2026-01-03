import net from "net";
import { SERVICE_PATTERNS } from "../shared/constants.js";
import type { IServiceFingerprint } from "../shared/types.js";

export class ServiceFingerprinter {
  async fingerprint(ip: string, port: number, banner?: string): Promise<IServiceFingerprint> {
    if (banner) {
      return this.analyzeBanner(banner);
    }

    try {
      if ([80, 443, 8080, 8443, 8000].includes(port)) {
        return await this.probeHTTP(ip, port);
      }

      if (port === 6379) {
        return await this.probeRedis(ip, port);
      }

      return await this.grabBanner(ip, port);
    } catch {
      return { identified: false };
    }
  }

  private analyzeBanner(banner: string): IServiceFingerprint {
    for (const pattern of SERVICE_PATTERNS.SSH) {
      const match = banner.match(pattern);
      if (match) {
        return {
          identified: true,
          service: "SSH",
          version: match[1],
          banner,
        };
      }
    }

    for (const pattern of SERVICE_PATTERNS.HTTP) {
      const match = banner.match(pattern);
      if (match) {
        return {
          identified: true,
          service: "HTTP",
          version: match[1],
          banner,
        };
      }
    }

    for (const pattern of SERVICE_PATTERNS.FTP) {
      const match = banner.match(pattern);
      if (match) {
        return {
          identified: true,
          service: "FTP",
          version: match[1] || "Unknown",
          banner,
        };
      }
    }

    for (const pattern of SERVICE_PATTERNS.SMTP) {
      const match = banner.match(pattern);
      if (match) {
        return {
          identified: true,
          service: "SMTP",
          version: match[1] || "Unknown",
          banner,
        };
      }
    }

    return { identified: false, banner };
  }

  private async probeHTTP(ip: string, port: number): Promise<IServiceFingerprint> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);

      let resolved = false;
      const safeResolve = (result: IServiceFingerprint) => {
        if (!resolved) {
          resolved = true;
          resolve(result);
        }
      };

      const httpRequest =
        `GET / HTTP/1.1\r\n` +
        `Host: ${ip}\r\n` +
        `User-Agent: PortScanner/1.0\r\n` +
        `Connection: close\r\n\r\n`;

      let response = "";

      socket.once("connect", () => {
        socket.write(httpRequest);
      });

      socket.on("data", (chunk: Buffer) => {
        response += chunk.toString("utf8");

        if (response.includes("\r\n\r\n")) {
          socket.end();
        }
      });

      socket.once("timeout", () => {
        socket.destroy();
        safeResolve({
          identified: false,
          banner: response || undefined,
        });
      });

      socket.once("error", () => {
        socket.destroy();
        safeResolve({
          identified: false,
          banner: response || undefined,
        });
      });

      socket.once("close", () => {
        const header = response.split("\r\n\r\n")[0];

        if (!header || !header.startsWith("HTTP/")) {
          safeResolve({
            identified: false,
            banner: header || undefined,
          });
          return;
        }

        const serverMatch = header.match(/Server:\s*([^\r\n]+)/i);
        const versionMatch = header.match(
          /(nginx|apache|iis|openresty|caddy|litespeed)[\/\s]?([\d.]+)?/i
        );

        safeResolve({
          identified: true,
          service: "HTTP",
          version: versionMatch
            ? versionMatch[2]
              ? `${versionMatch[1]}/${versionMatch[2]}`
              : versionMatch[1]
            : serverMatch?.[1],
          banner: header,
        });
      });

      socket.connect(port, ip);
    });
  }

  private async probeRedis(ip: string, port: number): Promise<IServiceFingerprint> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);

      let stage: "ping" | "info" | "done" = "ping";
      let infoBuffer = "";
      let resolved = false;

      const safeResolve = (result: IServiceFingerprint) => {
        if (!resolved) {
          resolved = true;
          resolve(result);
          socket.destroy();
        }
      };

      socket.once("connect", () => socket.write("PING\r\n"));

      socket.on("data", (chunk: Buffer) => {
        const str = chunk.toString("utf8");

        if (stage === "ping") {
          if (str.includes("+PONG")) {
            stage = "info";
            socket.write("INFO SERVER\r\n");
          } else {
            safeResolve({ identified: false, banner: str });
          }
          return;
        }

        if (stage === "info") {
          infoBuffer += str;

          if (infoBuffer.includes("\r\n")) {
            stage = "done";
            const versionMatch = infoBuffer.match(/redis_version:([\d.]+)/);
            safeResolve({
              identified: true,
              service: "Redis",
              version: versionMatch?.[1],
              banner: infoBuffer,
            });
          }
        }
      });

      socket.once("error", () => safeResolve({ identified: false }));
      socket.once("timeout", () => safeResolve({ identified: false }));
      socket.connect(port, ip);
    });
  }

  private async grabBanner(ip: string, port: number): Promise<IServiceFingerprint> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);

      let resolved = false;
      let banner = "";

      const safeResolve = (result: IServiceFingerprint) => {
        if (!resolved) {
          resolved = true;
          resolve(result);
          socket.destroy();
        }
      };

      socket.on("data", (chunk: Buffer) => {
        banner += chunk.toString("utf8", 0, Math.min(chunk.length, 512));
      });

      socket.once("error", () => safeResolve({ identified: false }));
      socket.once("timeout", () => safeResolve(banner ? this.analyzeBanner(banner) : { identified: false }));
      socket.once("close", () => safeResolve(banner ? this.analyzeBanner(banner) : { identified: false }));

      socket.connect(port, ip);
    });
  }
}
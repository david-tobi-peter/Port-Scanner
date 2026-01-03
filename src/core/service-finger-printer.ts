import net from "net";
import { SERVICE_PATTERNS } from "../shared/constants.js";
import type { IServiceFingerprint } from "../shared/types.js";

export class ServiceFingerprinter {
  async fingerprint(ip: string, port: number, banner?: string): Promise<IServiceFingerprint> {
    if (banner) {
      return this.analyzeBanner(banner, port);
    }

    try {
      if ([80, 443, 8080, 8443, 8000].includes(port)) {
        return await this.probeHTTP(ip, port);
      }

      if (port === 22) {
        return await this.grabBanner(ip, port);
      }

      if (port === 6379) {
        return await this.probeRedis(ip, port);
      }

      return await this.grabBanner(ip, port);
    } catch {
      return { identified: false };
    }
  }

  private analyzeBanner(banner: string, port: number): IServiceFingerprint {
    for (const pattern of SERVICE_PATTERNS.SSH) {
      const match = banner.match(pattern);
      if (match) {
        return {
          identified: true,
          service: "SSH",
          version: match[1],
          banner: banner.trim(),
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
          banner: banner.trim(),
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
          banner: banner.trim(),
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
          banner: banner.trim(),
        };
      }
    }

    const wellKnown: Record<number, string> = {
      80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
      25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL",
      6379: "Redis", 27017: "MongoDB",
    };

    if (wellKnown[port]) {
      return {
        identified: true,
        service: wellKnown[port],
        banner: banner.trim(),
      };
    }

    return { identified: false, banner: banner.trim() };
  }

  private async probeHTTP(ip: string, port: number): Promise<IServiceFingerprint> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);

      const httpRequest = `GET / HTTP/1.1\r\nHost: ${ip}\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n`;
      let response = "";

      socket.once("connect", () => socket.write(httpRequest));

      socket.on("data", (chunk: Buffer) => {
        response += chunk.toString();
        if (response.includes("\r\n\r\n")) socket.destroy();
      });

      socket.once("error", () => resolve({ identified: false }));

      socket.once("timeout", () => {
        socket.destroy();
        resolve({ identified: false });
      });

      socket.once("close", () => {
        const serverMatch = response.match(/Server:\s*(.+)/i);
        const versionMatch = response.match(/(nginx|Apache|IIS)\/([\d.]+)/i);

        if (serverMatch || versionMatch) {
          resolve({
            identified: true,
            service: "HTTP",
            version: versionMatch ? `${versionMatch[1]}/${versionMatch[2]}` : serverMatch?.[1],
            banner: response.split("\r\n\r\n")[0],
          });
        } else if (response.startsWith("HTTP/")) {
          resolve({
            identified: true,
            service: "HTTP",
            banner: response.split("\r\n\r\n")[0],
          });
        } else {
          resolve({ identified: false });
        }
      });

      socket.connect(port, ip);
    });
  }

  private async probeRedis(ip: string, port: number): Promise<IServiceFingerprint> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);
      let infoReceived = false;

      socket.once("connect", () => socket.write("PING\r\n"));

      socket.once("data", (chunk: Buffer) => {
        const response = chunk.toString();

        if (response.includes("+PONG")) {
          socket.write("INFO SERVER\r\n");
        } else {
          socket.destroy();
          resolve({ identified: false });
        }
      });

      socket.on("data", (chunk: Buffer) => {
        if (infoReceived) return;
        infoReceived = true;

        const info = chunk.toString();
        const versionMatch = info.match(/redis_version:([\d.]+)/);

        socket.destroy();

        if (versionMatch) {
          resolve({
            identified: true,
            service: "Redis",
            version: versionMatch[1],
          });
        } else if (info.includes("redis_version")) {
          resolve({
            identified: true,
            service: "Redis",
          });
        } else {
          resolve({ identified: false });
        }
      });

      socket.once("error", () => resolve({ identified: false }));
      socket.once("timeout", () => {
        socket.destroy();
        resolve({ identified: false });
      });

      socket.connect(port, ip);
    });
  }

  private async grabBanner(ip: string, port: number): Promise<IServiceFingerprint> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);
      let banner = "";

      socket.on("data", (chunk: Buffer) => {
        banner += chunk.toString("utf8", 0, Math.min(chunk.length, 512));
        socket.destroy();
      });

      socket.once("error", () => resolve({ identified: false }));

      socket.once("timeout", () => {
        socket.destroy();
        resolve(banner ? this.analyzeBanner(banner, port) : { identified: false });
      });

      socket.once("close", () => {
        resolve(banner ? this.analyzeBanner(banner, port) : { identified: false });
      });

      socket.connect(port, ip);
    });
  }
}
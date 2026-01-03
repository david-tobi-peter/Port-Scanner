import { IPortInfo, IScanOptions } from "./types.js";

export const WELL_KNOWN_PORTS: Record<number, IPortInfo> = {
  80: { service: "HTTP", category: "web", description: "Hypertext Transfer Protocol" },
  443: { service: "HTTPS", category: "web", description: "HTTP over TLS/SSL" },
  8080: { service: "HTTP-Alt", category: "web", description: "HTTP Alternate (Tomcat/Jenkins common)" },
  8443: { service: "HTTPS-Alt", category: "web", description: "HTTPS Alternate" },
  8000: { service: "HTTP-Alt", category: "web", description: "HTTP Alternate (Python/Django common)" },
  8888: { service: "HTTP-Alt", category: "web", description: "HTTP Alternate (Jupyter)" },

  22: { service: "SSH", category: "remote", description: "Secure Shell" },
  23: { service: "Telnet", category: "remote", description: "Telnet (INSECURE)" },
  3389: { service: "RDP", category: "remote", description: "Remote Desktop Protocol" },
  5900: { service: "VNC", category: "remote", description: "Virtual Network Computing" },
  5901: { service: "VNC", category: "remote", description: "VNC Display 1" },

  3306: { service: "MySQL", category: "database", description: "MySQL Database" },
  5432: { service: "PostgreSQL", category: "database", description: "PostgreSQL Database" },
  27017: { service: "MongoDB", category: "database", description: "MongoDB Database" },
  6379: { service: "Redis", category: "database", description: "Redis Key-Value Store" },
  9042: { service: "Cassandra", category: "database", description: "Apache Cassandra" },
  1433: { service: "MSSQL", category: "database", description: "Microsoft SQL Server" },
  5984: { service: "CouchDB", category: "database", description: "Apache CouchDB" },
  7474: { service: "Neo4j", category: "database", description: "Neo4j Graph Database" },

  5672: { service: "RabbitMQ", category: "messaging", description: "RabbitMQ AMQP" },
  15672: { service: "RabbitMQ-Mgmt", category: "messaging", description: "RabbitMQ Management" },
  9092: { service: "Kafka", category: "messaging", description: "Apache Kafka" },
  4222: { service: "NATS", category: "messaging", description: "NATS Messaging" },

  3000: { service: "Web Framework", category: "web-framework", description: "Node.js/React/Grafana (common dev port)" },
  3001: { service: "Web Framework", category: "web-framework", description: "Alternate dev server" },
  4200: { service: "Angular", category: "web-framework", description: "Angular CLI Dev Server" },
  5000: { service: "Web Framework", category: "web-framework", description: "Flask/Docker Registry (multi-purpose)" },
  9000: { service: "PHP-FPM", category: "web-framework", description: "PHP FastCGI" },

  25: { service: "SMTP", category: "email", description: "Simple Mail Transfer Protocol" },
  587: { service: "SMTP-Submit", category: "email", description: "SMTP Submission" },
  465: { service: "SMTPS", category: "email", description: "SMTP over SSL" },
  143: { service: "IMAP", category: "email", description: "Internet Message Access Protocol" },
  993: { service: "IMAPS", category: "email", description: "IMAP over SSL" },
  110: { service: "POP3", category: "email", description: "Post Office Protocol v3" },
  995: { service: "POP3S", category: "email", description: "POP3 over SSL" },

  53: { service: "DNS", category: "network", description: "Domain Name System" },
  67: { service: "DHCP", category: "network", description: "Dynamic Host Configuration" },
  68: { service: "DHCP-Client", category: "network", description: "DHCP Client" },
  161: { service: "SNMP", category: "network", description: "Simple Network Management" },

  2375: { service: "Docker", category: "container", description: "Docker API (Insecure)" },
  2376: { service: "Docker-TLS", category: "container", description: "Docker API over TLS" },
  6443: { service: "Kubernetes", category: "container", description: "Kubernetes API Server" },
  10250: { service: "Kubelet", category: "container", description: "Kubelet API" },
  2379: { service: "etcd", category: "container", description: "etcd Client API" },

  9090: { service: "Prometheus", category: "monitoring", description: "Prometheus Metrics" },
  9200: { service: "Elasticsearch", category: "monitoring", description: "Elasticsearch HTTP" },
  9300: { service: "Elasticsearch-Transport", category: "monitoring", description: "Elasticsearch Transport" },
  5601: { service: "Kibana", category: "monitoring", description: "Kibana Dashboard" },
};

export const DEFAULT_SCAN_OPTIONS: Required<IScanOptions> = {
  connectTimeout: 1000,
  idleObserve: 300,
  maxConcurrency: 200,
  stabilityRetries: 3,
  stabilityDelay: 400,
  enableFingerprinting: true,
  enableVulnerabilityChecks: true,
  portRange: { start: 1, end: 65535 },
};

export const SERVICE_PATTERNS = {
  SSH: [/SSH-[\d.]+-OpenSSH_([\d.]+[^\s]*)/i, /SSH-[\d.]+-(.+)/i],
  HTTP: [/Server:\s*(.+)/i, /nginx\/([\d.]+)/i, /Apache\/([\d.]+)/i],
  FTP: [/220.*FTP/i, /220\s+(.+)\s+FTP/i],
  SMTP: [/220\s+(.+)\s+ESMTP/i, /220.*SMTP/i],
  MySQL: [/\x00[\x00-\xFF]*?([\d.]+)[\x00-\xFF]*?mysql/i],
  PostgreSQL: [/PostgreSQL\s+([\d.]+)/i],
  Redis: [/\$\d+\r\n/],
};
export type Confidence = "high" | "medium" | "low";

export interface ServiceGuess {
  service: string;
  product: string;
  version: string;
  extrainfo: string;
  tunnel: string;
  confidence: Confidence;
  method: "banner" | "probe" | "port";
}

// Blackveil's own port-to-service table, based on IANA well-known assignments and common deployments.
export const PORT_SERVICES: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
  139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
  636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
  2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "http-alt", 5432: "postgresql",
  5601: "kibana", 5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes-api",
  7001: "weblogic", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8088: "http-alt",
  8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
  9418: "git", 10000: "webmin", 11211: "memcached", 27017: "mongodb", 50000: "http-alt",
};

export const QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017];

export const STANDARD_PORTS = [...new Set([
  ...QUICK_PORTS, 111, 135, 139, 389, 636, 1080, 1521, 1723, 2049, 2375, 2376, 3000, 5000, 5601, 5672, 5985, 5986, 6443,
  7001, 8000, 8008, 8081, 8088, 8888, 9000, 9090, 9300, 9418, 10000, 11211, 50000,
  20, 26, 37, 79, 81, 88, 106, 113, 119, 144, 179, 199, 427, 444, 513, 514, 515, 543, 544, 548, 554, 631, 646, 873,
  990, 1025, 1026, 1027, 1110, 1720, 1755, 1900, 2000, 2001, 2121, 2717, 3128, 3986, 4899, 5009, 5051, 5060, 5101,
  5190, 5357, 5631, 5666, 5800, 6000, 6001, 6646, 7070, 8009, 8031, 9100, 9999, 10001, 32768, 49152, 49153, 49154,
])].slice(0, 100);

export const TLS_PORTS = new Set([443, 465, 636, 993, 995, 2376, 5986, 6443, 8443]);
export const HTTP_PORTS = new Set([80, 81, 3000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 9200, 10000, 50000]);

// eslint-disable-next-line no-control-regex
const clean = (s: string, n: number) => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);

export function portGuess(port: number): ServiceGuess {
  const service = PORT_SERVICES[port] ?? "unknown";
  return { service, product: "", version: "", extrainfo: "", tunnel: TLS_PORTS.has(port) ? "ssl" : "", confidence: "low", method: "port" };
}

function mysqlVersion(b: Uint8Array): string | null {
  if (b.length < 6 || b[4] !== 10) return null;
  let end = 5;
  while (end < b.length && end < 64 && b[end] !== 0) end++;
  const v = new TextDecoder().decode(b.subarray(5, end));
  return /^\d+\.\d+/.test(v) ? v : null;
}

export function fromBanner(port: number, bytes: Uint8Array): ServiceGuess | null {
  if (!bytes.length) return null;
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 512));
  const base = { extrainfo: "", tunnel: "", confidence: "high" as Confidence, method: "banner" as const };
  let m = /^SSH-([\d.]+)-([^\s\r\n]+)/.exec(text);
  if (m) {
    const [prod, ver] = m[2].split(/[_-](?=\d)/);
    return { ...base, service: "ssh", product: clean(prod, 60), version: clean(ver ?? "", 40), extrainfo: `protocol ${m[1]}` };
  }
  const mv = mysqlVersion(bytes);
  if (mv) return { ...base, service: "mysql", product: /mariadb/i.test(mv) ? "MariaDB" : "MySQL", version: clean(mv.replace(/-.*$/, ""), 40) };
  if (/^220[ -]/.test(text)) {
    if (/ftp/i.test(text) || port === 21) {
      m = /(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service)[ /]?([\d.]*)/i.exec(text);
      return { ...base, service: "ftp", product: clean(m?.[1] ?? "", 60), version: clean(m?.[2] ?? "", 40), confidence: m ? "high" : "medium" };
    }
    m = /(Postfix|Exim|Sendmail|Microsoft ESMTP MAIL Service|OpenSMTPD|Haraka)[ /]?([\d.]*)/i.exec(text);
    return { ...base, service: "smtp", product: clean(m?.[1] ?? "", 60), version: clean(m?.[2] ?? "", 40), confidence: m ? "high" : "medium" };
  }
  if (/^\+OK/.test(text)) return { ...base, service: "pop3", product: clean(/Dovecot/i.test(text) ? "Dovecot" : "", 40), version: "", confidence: "medium" };
  if (/^\* OK/.test(text)) return { ...base, service: "imap", product: clean(/Dovecot/i.test(text) ? "Dovecot" : "", 40), version: "", confidence: "medium" };
  if (/^RFB \d{3}\.\d{3}/.test(text)) return { ...base, service: "vnc", product: "", version: clean(text.slice(4, 11), 10) };
  if (/^-(ERR|NOAUTH)|^\+PONG/.test(text)) return { ...base, service: "redis", product: "Redis", version: "", confidence: "medium" };
  if (/^HTTP\/\d/.test(text)) return fromHttp(text, false);
  return { ...base, service: PORT_SERVICES[port] ?? "unknown", product: "", version: "", extrainfo: `banner: ${clean(text, 80)}`, confidence: "low" };
}

export function fromHttp(text: string, tls: boolean): ServiceGuess {
  const server = /^server:\s*(.+)$/im.exec(text)?.[1] ?? "";
  const powered = /^x-powered-by:\s*(.+)$/im.exec(text)?.[1] ?? "";
  const m = /^([A-Za-z][\w .-]*?)(?:\/([\d][\w.-]*))?(?:\s|$)/.exec(server.trim());
  return {
    service: tls ? "https" : "http", product: clean(m?.[1] ?? server, 60), version: clean(m?.[2] ?? "", 40),
    extrainfo: clean(powered ? `powered by ${powered}` : "", 80), tunnel: tls ? "ssl" : "",
    confidence: "high", method: "probe",
  };
}
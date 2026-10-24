// Native ASN.1/DER parser for X.509 certificates. Pure functions with no network
// or platform dependencies, so the parser logic can be unit-tested in isolation and
// reused by any engine module.

export interface Tlv {
  tag: number;
  cls: number; // 0 universal, 1 application, 2 context-specific, 3 private
  constructed: boolean;
  value: Uint8Array;
  /** Byte-slices of the child TLVs, populated when constructed. */
  children: Tlv[];
  /** Absolute offset of this TLV's header within the source buffer. */
  offset: number;
  /** Full encoded length (header + value). */
  length: number;
}

export interface TimeValue {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

export interface AlgorithmId {
  oid: string;
  name: string;
}

export interface X509Cert {
  subject: string;
  issuer: string;
  serial: string;
  notBefore: TimeValue;
  notAfter: TimeValue;
  signatureAlgorithm: AlgorithmId;
  publicKeyAlgorithm: AlgorithmId;
  publicKeyBits: number | null;
  subjectAltNames: string[];
  version: number;
  raw: Uint8Array;
}

const OID_NAMES: Record<string, string> = {
  "1.2.840.113549.1.1.11": "SHA-256 with RSA",
  "1.2.840.113549.1.1.12": "SHA-384 with RSA",
  "1.2.840.113549.1.1.13": "SHA-512 with RSA",
  "1.2.840.113549.1.1.14": "SHA-224 with RSA",
  "1.2.840.113549.1.1.5": "SHA-1 with RSA",
  "1.2.840.113549.1.1.4": "MD5 with RSA",
  "1.2.840.113549.1.1.10": "RSA-PSS",
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.10045.4.1": "EC",
  "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
  "1.2.840.10045.4.3.3": "ECDSA with SHA-384",
  "1.2.840.10045.4.3.4": "ECDSA with SHA-512",
  "1.2.840.10045.4.3.1": "ECDSA with SHA-1",
  "1.2.840.113549.1.1.7": "RSAES-OAEP",
};

const OID_SAN = "2.5.29.17";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";

class DerError extends Error {}

function readLength(buf: Uint8Array, pos: number): { length: number; headerBytes: number } {
  if (pos >= buf.length) throw new DerError("truncated length");
  const first = buf[pos];
  if (first < 0x80) return { length: first, headerBytes: 1 };
  const count = first & 0x7f;
  if (count === 0) return { length: -1, headerBytes: 1 }; // indefinite (not valid in DER here)
  if (count > 4) throw new DerError("unsupported length");
  if (pos + 1 + count > buf.length) throw new DerError("truncated long length");
  let length = 0;
  for (let i = 0; i < count; i++) {
    length = (length << 8) | buf[pos + 1 + i];
  }
  return { length, headerBytes: 1 + count };
}

function readTag(buf: Uint8Array, pos: number): { tag: number; cls: number; constructed: boolean; headerBytes: number } {
  const first = buf[pos];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let headerBytes = 1;
  if (tag === 0x1f) {
    tag = 0;
    while (true) {
      const b = buf[pos + headerBytes];
      tag = (tag << 7) | (b & 0x7f);
      headerBytes++;
      if ((b & 0x80) === 0) break;
    }
  }
  return { tag, cls, constructed, headerBytes };
}

export function parseTlv(buf: Uint8Array, offset = 0): Tlv {
  if (offset >= buf.length) throw new DerError("out of bounds");
  const { tag, cls, constructed, headerBytes: tagBytes } = readTag(buf, offset);
  const { length, headerBytes: lenBytes } = readLength(buf, offset + tagBytes);
  if (length < 0) throw new DerError("indefinite length not supported");
  const contentStart = offset + tagBytes + lenBytes;
  const end = contentStart + length;
  if (end > buf.length) throw new DerError("truncated value");
  const value = buf.subarray(contentStart, end);
  const node: Tlv = { tag, cls, constructed, value, children: [], offset, length: tagBytes + lenBytes + length };

  if (constructed) {
    let p = 0;
    while (p < value.length) {
      const child = parseTlv(value, p);
      node.children.push(child);
      p += child.length;
    }
    if (p !== value.length) throw new DerError("malformed children");
  }
  return node;
}

function decodeTime(tlv: Tlv): TimeValue {
  const s = new TextDecoder().decode(tlv.value);
  const isUtc = tlv.tag === 0x17;
  if (!isUtc && tlv.tag !== 0x18) throw new DerError("not a time");
  const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/.exec(s) ?? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/.exec(s);
  if (!m) throw new DerError("unreadable time: " + s);
  const groups = m.slice(1).map(Number);
  if (groups[0] < 100 && isUtc) groups[0] += groups[0] < 50 ? 2000 : 1900;
  const [year, month, day, hour, minute, second] = groups;
  return { year, month, day, hour, minute, second };
}

function decodeOid(tlv: Tlv): string {
  const v = tlv.value;
  if (v.length === 0) return "";
  const parts: number[] = [];
  const firstByte = v[0];
  // First subidentifier is encoded in the first byte (X.690 8.19.4).
  if (firstByte < 40) { parts.push(0, firstByte); }
  else if (firstByte < 80) { parts.push(1, firstByte - 40); }
  else { parts.push(2, firstByte - 80); }
  let value = 0;
  for (let i = 1; i < v.length; i++) {
    const b = v[i];
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) { parts.push(value); value = 0; }
  }
  return parts.join(".");
}

function bytesToHex(b: Uint8Array, max = 40): string {
  let hex = "";
  for (let i = 0; i < b.length && hex.length < max * 2; i++) hex += b[i].toString(16).padStart(2, "0");
  return hex;
}

const NAME_OIDS: Record<string, string> = {
  "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
  "2.5.4.9": "STREET", "2.5.4.12": "TITLE", "2.5.4.42": "GIVENNAME", "2.5.4.4": "SURNAME",
};

function decodeName(tlv: Tlv): string {
  const rdns: string[] = [];
  for (const rdn of tlv.children) {
    // RDN = SET OF AttributeTypeAndValue
    for (const atv of rdn.children) {
      if (atv.children.length !== 2) continue;
      const oid = decodeOid(atv.children[0]);
      const label = NAME_OIDS[oid] ?? oid;
      const value = decodeX520(atv.children[1]);
      if (value) rdns.push(`${label}=${value}`);
    }
  }
  return rdns.join(", ");
}

function decodeX520(tlv: Tlv): string {
  if (tlv.tag === 0x0c) return new TextDecoder().decode(tlv.value).replace(/[\x00-\x1f]/g, "").trim();
  if (tlv.tag === 0x13) { // PrintableString
    return new TextDecoder().decode(tlv.value).trim();
  }
  if (tlv.tag === 0x16 || tlv.tag === 0x1e) return new TextDecoder().decode(tlv.value).trim();
  if (tlv.tag === 0x10) { // nested (not used for normal names)
    return decodeName(tlv);
  }
  // Unknown string types: render as hex
  return "#" + bytesToHex(tlv.value, 20);
}

function readAlgorithm(tlv: Tlv): AlgorithmId {
  const oidTlv = tlv.children[0];
  if (!oidTlv) return { oid: "", name: "unknown" };
  const oid = decodeOid(oidTlv);
  return { oid, name: OID_NAMES[oid] ?? oid };
}

function readExtensions(tbsChildren: Tlv[]): Tlv[] {
  for (const c of tbsChildren) {
    if (c.cls === 2 && c.tag === 3 && c.constructed) {
      return c.children[0]?.children ?? [];
    }
  }
  return [];
}

function readSanNames(exts: Tlv[]): string[] {
  const names: string[] = [];
  for (const ext of exts) {
    if (ext.children.length < 2) continue;
    const oid = decodeOid(ext.children[0]);
    if (oid !== OID_SAN) continue;
    const raw = ext.children[1]?.value;
    if (!raw) continue;
    let generalNames: Tlv;
    try {
      generalNames = parseTlv(raw);
    } catch {
      continue;
    }
    for (const gn of generalNames.children) {
      if (gn.cls === 2 && gn.tag === 2) names.push(new TextDecoder().decode(gn.value).trim());
    }
  }
  return names;
}

function readKeyInfo(spki: Tlv | undefined): { algorithm: AlgorithmId; bits: number | null } {
  if (!spki || spki.tag !== 0x10 || spki.cls !== 0 || spki.children.length < 2) {
    return { algorithm: { oid: "", name: "unknown" }, bits: null };
  }
  const algorithm = readAlgorithm(spki.children[0]);
  const bitsTlv = spki.children[1]; // BIT STRING
  if (bitsTlv.tag !== 0x03) return { algorithm, bits: null };
  // BIT STRING: first byte is unused-bits count, rest is subjectPublicKey
  const key = bitsTlv.value.subarray(1);
  try {
    const keyNode = parseTlv(key);
    if (algorithm.oid === "1.2.840.113549.1.1.1" || algorithm.oid.endsWith(".113549.1.1.1")) {
      // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
      const modulus = keyNode.children[0];
      if (modulus && modulus.tag === 0x02) {
        const bytes = modulus.value;
        let first = 0;
        while (first < bytes.length - 1 && bytes[first] === 0) first++;
        return { algorithm, bits: (bytes.length - first) * 8 };
      }
    }
    if (algorithm.oid === "1.2.840.10045.4.1") {
      // subjectPublicKey is the EC point; key size from the named curve params.
      const params = spki.children[0].children[1];
      if (params) return { algorithm, bits: ecCurveBits(decodeOid(params)) };
    }
  } catch {
    /* fall through with null bits */
  }
  return { algorithm, bits: null };
}

function ecCurveBits(oid: string): number | null {
  if (/1\.2\.840\.10045\.3\.1\.7$/.test(oid)) return 256; // P-256
  if (/1\.3\.132\.0\.34$/.test(oid)) return 384; // P-384
  if (/1\.3\.132\.0\.35$/.test(oid)) return 521; // P-521
  if (/1\.3\.132\.0\.10$/.test(oid)) return 256; // secp256k1
  return null;
}

export function parseCertificate(bytes: Uint8Array): X509Cert {
  const root = parseTlv(bytes);
  if (root.tag !== 0x10 || !root.constructed) throw new DerError("not a certificate");
  const tbs = root.children[0];
  if (!tbs || tbs.tag !== 0x10) throw new DerError("missing TBS certificate");
  const sigAlg = readAlgorithm(root.children[1] ?? { children: [], value: new Uint8Array() } as unknown as Tlv);

  let version = 1;
  let idx = 0;
  if (tbs.children[0]?.cls === 2 && tbs.children[0].tag === 0) {
    const vInt = tbs.children[0].children[0];
    if (vInt && vInt.tag === 0x02 && vInt.value.length) version = vInt.value[vInt.value.length - 1] + 1;
    idx = 1;
  }
  const rest = tbs.children.slice(idx);
  // rest[0] = serialNumber, rest[1] = signature AlgorithmIdentifier, rest[2] = issuer, rest[3] = validity, rest[4] = subject, rest[5] = spki
  const serial = bytesToHex(rest[0]?.value ?? new Uint8Array(), 40);
  const issuer = decodeName(rest[2] ?? ({ children: [] } as unknown as Tlv));
  const validity = rest[3];
  let notBefore: TimeValue = { year: 0, month: 0, day: 0, hour: 0, minute: 0, second: 0 };
  let notAfter: TimeValue = { ...notBefore };
  if (validity && validity.children.length === 2) {
    notBefore = decodeTime(validity.children[0]);
    notAfter = decodeTime(validity.children[1]);
  }
  const subject = decodeName(rest[4] ?? ({ children: [] } as unknown as Tlv));
  const keyInfo = readKeyInfo(rest[5]);
  const exts = readExtensions(tbs.children);
  const sans = readSanNames(exts);

  return {
    subject,
    issuer,
    serial,
    notBefore,
    notAfter,
    signatureAlgorithm: sigAlg,
    publicKeyAlgorithm: keyInfo.algorithm,
    publicKeyBits: keyInfo.bits,
    subjectAltNames: sans,
    version,
    raw: bytes,
  };
}

export function timeToMs(t: TimeValue): number {
  return Date.UTC(t.year, t.month - 1, t.day, t.hour, t.minute, t.second);
}

export function daysRemaining(notAfter: TimeValue, now = Date.now()): number {
  return Math.floor((timeToMs(notAfter) - now) / 86_400_000);
}

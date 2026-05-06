/**
 * Common types and constants for the Packet Analyzer and DPI Engine
 */

export const EtherType = {
  IPv4: 0x0800,
  IPv6: 0x86dd,
  ARP: 0x0806,
  VLAN: 0x8100
};

export const Protocol = {
  ICMP: 1,
  TCP: 6,
  UDP: 17
};

export const TCPFlags = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
};

export const AppType = {
  UNKNOWN: 0,
  HTTP: 1,
  HTTPS: 2,
  DNS: 3,
  TLS: 4,
  QUIC: 5,
  GOOGLE: 6,
  FACEBOOK: 7,
  YOUTUBE: 8,
  TWITTER: 9,
  INSTAGRAM: 10,
  NETFLIX: 11,
  AMAZON: 12,
  MICROSOFT: 13,
  APPLE: 14,
  WHATSAPP: 15,
  TELEGRAM: 16,
  TIKTOK: 17,
  SPOTIFY: 18,
  ZOOM: 19,
  DISCORD: 20,
  GITHUB: 21,
  CLOUDFLARE: 22
};

export const AppTypeNames = {
  [AppType.UNKNOWN]: "UNKNOWN",
  [AppType.HTTP]: "HTTP",
  [AppType.HTTPS]: "HTTPS",
  [AppType.DNS]: "DNS",
  [AppType.TLS]: "TLS",
  [AppType.QUIC]: "QUIC",
  [AppType.GOOGLE]: "Google",
  [AppType.FACEBOOK]: "Facebook",
  [AppType.YOUTUBE]: "YouTube",
  [AppType.TWITTER]: "Twitter/X",
  [AppType.INSTAGRAM]: "Instagram",
  [AppType.NETFLIX]: "Netflix",
  [AppType.AMAZON]: "Amazon",
  [AppType.MICROSOFT]: "Microsoft",
  [AppType.APPLE]: "Apple",
  [AppType.WHATSAPP]: "WhatsApp",
  [AppType.TELEGRAM]: "Telegram",
  [AppType.TIKTOK]: "TikTok",
  [AppType.SPOTIFY]: "Spotify",
  [AppType.ZOOM]: "Zoom",
  [AppType.DISCORD]: "Discord",
  [AppType.GITHUB]: "GitHub",
  [AppType.CLOUDFLARE]: "Cloudflare"
};

export const ConnectionState = {
  NEW: 'NEW',
  ESTABLISHED: 'ESTABLISHED',
  CLASSIFIED: 'CLASSIFIED',
  BLOCKED: 'BLOCKED',
  CLOSED: 'CLOSED'
};

export const PacketAction = {
  FORWARD: 'FORWARD',
  DROP: 'DROP',
  INSPECT: 'INSPECT',
  LOG_ONLY: 'LOG_ONLY'
};

export class FiveTuple {
  constructor(srcIp, dstIp, srcPort, dstPort, protocol) {
    this.srcIp = srcIp;
    this.dstIp = dstIp;
    this.srcPort = srcPort;
    this.dstPort = dstPort;
    this.protocol = protocol;
  }

  equals(other) {
    return this.srcIp === other.srcIp &&
           this.dstIp === other.dstIp &&
           this.srcPort === other.srcPort &&
           this.dstPort === other.dstPort &&
           this.protocol === other.protocol;
  }

  reverse() {
    return new FiveTuple(this.dstIp, this.srcIp, this.dstPort, this.srcPort, this.protocol);
  }

  toString() {
    const proto = this.protocol === Protocol.TCP ? 'TCP' : (this.protocol === Protocol.UDP ? 'UDP' : this.protocol);
    return `${this.srcIp}:${this.srcPort} -> ${this.dstIp}:${this.dstPort} (${proto})`;
  }

  getHash() {
    // A simple hash for the tuple
    return `${this.srcIp}_${this.dstIp}_${this.srcPort}_${this.dstPort}_${this.protocol}`;
  }
}

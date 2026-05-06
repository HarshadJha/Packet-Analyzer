import { EtherType, Protocol, TCPFlags } from './types.js';

export class ParsedPacket {
  constructor() {
    this.timestampSec = 0;
    this.timestampUsec = 0;
    this.srcMac = "";
    this.destMac = "";
    this.etherType = 0;
    this.hasIp = false;
    this.ipVersion = 0;
    this.srcIp = "";
    this.destIp = "";
    this.protocol = 0;
    this.ttl = 0;
    this.hasTcp = false;
    this.hasUdp = false;
    this.srcPort = 0;
    this.destPort = 0;
    this.tcpFlags = 0;
    this.seqNumber = 0;
    this.ackNumber = 0;
    this.payloadLength = 0;
    this.payloadData = null;
  }
}

export class PacketParser {
  static parse(raw) {
    const parsed = new ParsedPacket();
    parsed.timestampSec = raw.header.ts_sec;
    parsed.timestampUsec = raw.header.ts_usec;

    const data = raw.data;
    const len = data.length;
    let offset = 0;

    // Parse Ethernet
    if (len < 14) return null;
    parsed.destMac = PacketParser.macToString(data, 0);
    parsed.srcMac = PacketParser.macToString(data, 6);
    parsed.etherType = data.readUInt16BE(12);
    offset = 14;

    // Parse IP
    if (parsed.etherType === EtherType.IPv4) {
      if (len < offset + 20) return parsed;
      
      const versionIhl = data[offset];
      parsed.ipVersion = (versionIhl >> 4) & 0x0F;
      const ihl = versionIhl & 0x0F;
      const ipHeaderLen = ihl * 4;

      if (parsed.ipVersion !== 4 || len < offset + ipHeaderLen) return parsed;

      parsed.ttl = data[offset + 8];
      parsed.protocol = data[offset + 9];
      parsed.srcIp = PacketParser.ipToString(data, offset + 12);
      parsed.destIp = PacketParser.ipToString(data, offset + 16);
      parsed.hasIp = true;
      
      const transportOffset = offset + ipHeaderLen;
      offset = transportOffset;

      // Parse Transport
      if (parsed.protocol === Protocol.TCP) {
        if (len < offset + 20) return parsed;
        parsed.srcPort = data.readUInt16BE(offset);
        parsed.destPort = data.readUInt16BE(offset + 2);
        parsed.seqNumber = data.readUInt32BE(offset + 4);
        parsed.ackNumber = data.readUInt32BE(offset + 8);
        
        const dataOffset = (data[offset + 12] >> 4) & 0x0F;
        const tcpHeaderLen = dataOffset * 4;
        parsed.tcpFlags = data[offset + 13];
        
        parsed.hasTcp = true;
        offset += tcpHeaderLen;
      } else if (parsed.protocol === Protocol.UDP) {
        if (len < offset + 8) return parsed;
        parsed.srcPort = data.readUInt16BE(offset);
        parsed.destPort = data.readUInt16BE(offset + 2);
        parsed.hasUdp = true;
        offset += 8;
      }
    }

    if (offset < len) {
      parsed.payloadLength = len - offset;
      parsed.payloadData = data.slice(offset);
    }

    return parsed;
  }

  static macToString(data, offset) {
    return Array.from(data.slice(offset, offset + 6))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':');
  }

  static ipToString(data, offset) {
    return `${data[offset]}.${data[offset+1]}.${data[offset+2]}.${data[offset+3]}`;
  }

  static protocolToString(protocol) {
    switch (protocol) {
      case Protocol.ICMP: return "ICMP";
      case Protocol.TCP: return "TCP";
      case Protocol.UDP: return "UDP";
      default: return `Unknown(${protocol})`;
    }
  }

  static tcpFlagsToString(flags) {
    const result = [];
    if (flags & TCPFlags.SYN) result.push("SYN");
    if (flags & TCPFlags.ACK) result.push("ACK");
    if (flags & TCPFlags.FIN) result.push("FIN");
    if (flags & TCPFlags.RST) result.push("RST");
    if (flags & TCPFlags.PSH) result.push("PSH");
    if (flags & TCPFlags.URG) result.push("URG");
    return result.length > 0 ? result.join(" ") : "none";
  }
}

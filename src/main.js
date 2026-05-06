#!/usr/bin/env node
import { PcapReader } from './pcap_io.js';
import { PacketParser } from './packet_parser.js';
import { EtherType, AppType } from './types.js';

function printPacketSummary(pkt, packetNum) {
  const date = new Date(pkt.timestampSec * 1000);
  const timeStr = date.toISOString().replace('T', ' ').replace('Z', '');
  
  console.log(`\n========== Packet #${packetNum} ==========`);
  console.log(`Time: ${timeStr}.${pkt.timestampUsec.toString().padStart(6, '0')}`);
  
  console.log(`\n[Ethernet]`);
  console.log(`  Source MAC:      ${pkt.srcMac}`);
  console.log(`  Destination MAC: ${pkt.destMac}`);
  let etherTypeName = `0x${pkt.etherType.toString(16).padStart(4, '0')}`;
  if (pkt.etherType === EtherType.IPv4) etherTypeName += " (IPv4)";
  else if (pkt.etherType === EtherType.IPv6) etherTypeName += " (IPv6)";
  else if (pkt.etherType === EtherType.ARP) etherTypeName += " (ARP)";
  console.log(`  EtherType:       ${etherTypeName}`);

  if (pkt.hasIp) {
    console.log(`\n[IPv${pkt.ipVersion}]`);
    console.log(`  Source IP:      ${pkt.srcIp}`);
    console.log(`  Destination IP: ${pkt.destIp}`);
    console.log(`  Protocol:       ${PacketParser.protocolToString(pkt.protocol)}`);
    console.log(`  TTL:            ${pkt.ttl}`);
  }

  if (pkt.hasTcp) {
    console.log(`\n[TCP]`);
    console.log(`  Source Port:      ${pkt.srcPort}`);
    console.log(`  Destination Port: ${pkt.destPort}`);
    console.log(`  Sequence Number:  ${pkt.seqNumber}`);
    console.log(`  Ack Number:       ${pkt.ackNumber}`);
    console.log(`  Flags:            ${PacketParser.tcpFlagsToString(pkt.tcpFlags)}`);
  }

  if (pkt.hasUdp) {
    console.log(`\n[UDP]`);
    console.log(`  Source Port:      ${pkt.srcPort}`);
    console.log(`  Destination Port: ${pkt.destPort}`);
  }

  if (pkt.payloadLength > 0) {
    console.log(`\n[Payload]`);
    console.log(`  Length: ${pkt.payloadLength} bytes`);
    
    const previewLen = Math.min(pkt.payloadLength, 32);
    let preview = "";
    for (let i = 0; i < previewLen; i++) {
      preview += pkt.payloadData[i].toString(16).padStart(2, '0') + " ";
    }
    if (pkt.payloadLength > 32) preview += "...";
    console.log(`  Preview: ${preview}`);
  }
}

function printUsage() {
  console.log("Usage: node src/main.js <pcap_file> [max_packets]");
  console.log("\nArguments:");
  console.log("  pcap_file   - Path to a .pcap file");
  console.log("  max_packets - (Optional) Maximum number of packets to display");
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    printUsage();
    process.exit(1);
  }

  const filename = args[0];
  const maxPackets = args[1] ? parseInt(args[1]) : Infinity;

  console.log("====================================");
  console.log("     Packet Analyzer v1.0 (JS)");
  console.log("====================================\n");

  const reader = new PcapReader();
  if (!(await reader.open(filename))) {
    process.exit(1);
  }

  let count = 0;
  let raw;
  while (count < maxPackets && (raw = await reader.readNextPacket())) {
    const parsed = PacketParser.parse(raw);
    if (parsed) {
      count++;
      printPacketSummary(parsed, count);
    }
  }

  console.log(`\nRead ${count} packets.`);
  await reader.close();
}

main();

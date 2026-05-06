import { PcapReader, PcapWriter } from './pcap_io.js';
import { PacketParser } from './packet_parser.js';
import { RuleManager } from './rule_manager.js';
import { ConnectionTracker, GlobalConnectionTable } from './connection_tracker.js';
import { SNIExtractor, HTTPHostExtractor, DNSExtractor, sniToAppType } from './dpi_utils.js';
import { AppType, PacketAction, ConnectionState, FiveTuple, Protocol } from './types.js';

export class DPIEngine {
  constructor(config = {}) {
    this.config = {
      numLoadBalancers: 2,
      fpsPerLb: 2,
      rulesFile: '',
      ...config
    };
    this.ruleManager = new RuleManager();
    this.globalConnTable = new GlobalConnectionTable();
    this.trackers = [];
    this.stats = {
      totalPackets: 0,
      totalBytes: 0,
      tcpPackets: 0,
      udpPackets: 0,
      forwardedPackets: 0,
      droppedPackets: 0
    };
    this.running = false;
  }

  initialize() {
    if (this.config.rulesFile) {
      this.ruleManager.loadRules(this.config.rulesFile);
    }

    const totalFps = this.config.numLoadBalancers * this.config.fpsPerLb;
    for (let i = 0; i < totalFps; i++) {
      const tracker = new ConnectionTracker(i);
      this.trackers.push(tracker);
      this.globalConnTable.registerTracker(tracker);
    }

    console.log(`[DPIEngine] Initialized with ${totalFps} trackers`);
    return true;
  }

  async processFile(inputFile, outputFile) {
    console.log(`\n[DPIEngine] Processing: ${inputFile}`);
    console.log(`[DPIEngine] Output to:  ${outputFile}\n`);

    this.initialize();

    const reader = new PcapReader();
    if (!(await reader.open(inputFile))) return false;

    const writer = new PcapWriter();
    if (!(await writer.open(outputFile, reader.globalHeader))) {
      await reader.close();
      return false;
    }

    let packetId = 0;
    let raw;
    while ((raw = await reader.readNextPacket())) {
      const parsed = PacketParser.parse(raw);
      if (!parsed) continue;

      if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
        // Just forward non-IP/non-TCP/UDP packets for now if we want full transparency
        // Or skip them as the C++ version does
        continue;
      }

      this.stats.totalPackets++;
      this.stats.totalBytes += raw.data.length;
      if (parsed.hasTcp) this.stats.tcpPackets++;
      else if (parsed.hasUdp) this.stats.udpPackets++;

      const tuple = new FiveTuple(
        RuleManager.parseIP(parsed.srcIp),
        RuleManager.parseIP(parsed.destIp),
        parsed.srcPort,
        parsed.destPort,
        parsed.protocol
      );

      // Simple load balancing: pick tracker based on tuple hash
      const hashStr = tuple.getHash();
      let h = 0;
      for (let i = 0; i < hashStr.length; i++) {
        h = (h * 31 + hashStr.charCodeAt(i)) | 0;
      }
      const trackerIdx = Math.abs(h) % this.trackers.length;
      const tracker = this.trackers[trackerIdx];

      const action = this.processPacket(raw, parsed, tuple, tracker);

      if (action !== PacketAction.DROP) {
        await writer.writePacket(raw.header, raw.data);
        this.stats.forwardedPackets++;
      } else {
        this.stats.droppedPackets++;
      }

      packetId++;
      if (packetId % 1000 === 0) {
        process.stdout.write(`\rProcessed ${packetId} packets...`);
      }
    }

    console.log(`\n[Reader] Finished reading ${packetId} packets`);
    await reader.close();
    await writer.close();

    console.log(this.globalConnTable.generateReport());
    this.printFinalStats();

    return true;
  }

  processPacket(raw, parsed, tuple, tracker) {
    const conn = tracker.getOrCreateConnection(tuple);
    tracker.updateConnection(conn, raw.data.length, true);

    if (conn.state === ConnectionState.BLOCKED) {
      return PacketAction.DROP;
    }

    if (conn.state !== ConnectionState.CLASSIFIED && parsed.payloadLength > 0) {
      this.inspectPayload(parsed, conn, tracker);
    }

    const blockReason = this.ruleManager.shouldBlock(
      tuple.srcIp,
      tuple.dstPort,
      conn.appType,
      conn.sni
    );

    if (blockReason) {
      console.log(`\n[BLOCK] ${blockReason.type} ${blockReason.value} on connection ${tuple.toString()}`);
      tracker.blockConnection(conn);
      return PacketAction.DROP;
    }

    return PacketAction.FORWARD;
  }

  inspectPayload(parsed, conn, tracker) {
    const payload = parsed.payloadData;
    
    // TLS SNI
    const sni = SNIExtractor.extract(payload);
    if (sni) {
      const app = sniToAppType(sni, AppType);
      tracker.classifyConnection(conn, app, sni);
      return;
    }

    // HTTP Host
    if (parsed.destPort === 80) {
      const host = HTTPHostExtractor.extract(payload);
      if (host) {
        const app = sniToAppType(host, AppType);
        tracker.classifyConnection(conn, app, host);
        return;
      }
    }

    // DNS
    if (parsed.destPort === 53 || parsed.srcPort === 53) {
      const domain = DNSExtractor.extractQuery(payload);
      if (domain) {
        tracker.classifyConnection(conn, AppType.DNS, domain);
        return;
      }
    }

    // Fallback
    if (parsed.destPort === 80) {
      tracker.classifyConnection(conn, AppType.HTTP, "");
    } else if (parsed.destPort === 443) {
      tracker.classifyConnection(conn, AppType.HTTPS, "");
    }
  }

  printFinalStats() {
    console.log("\n" + "=".repeat(60));
    console.log("                DPI ENGINE FINAL STATS");
    console.log("=".repeat(60));
    console.log(`Total Packets:     ${this.stats.totalPackets.toString().padStart(10)}`);
    console.log(`Total Bytes:       ${this.stats.totalBytes.toString().padStart(10)}`);
    console.log(`TCP Packets:       ${this.stats.tcpPackets.toString().padStart(10)}`);
    console.log(`UDP Packets:       ${this.stats.udpPackets.toString().padStart(10)}`);
    console.log(`Forwarded:         ${this.stats.forwardedPackets.toString().padStart(10)}`);
    console.log(`Dropped:           ${this.stats.droppedPackets.toString().padStart(10)}`);
    console.log("=".repeat(60) + "\n");
  }
}

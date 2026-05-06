import { ConnectionState, PacketAction, AppType, AppTypeNames } from './types.js';

export class Connection {
  constructor(tuple) {
    this.tuple = tuple;
    this.state = ConnectionState.NEW;
    this.appType = AppType.UNKNOWN;
    this.sni = "";
    this.packetsIn = 0;
    this.packetsOut = 0;
    this.bytesIn = 0;
    this.bytesOut = 0;
    this.firstSeen = Date.now();
    this.lastSeen = this.firstSeen;
    this.action = PacketAction.FORWARD;
    this.synSeen = false;
    this.synAckSeen = false;
    this.finSeen = false;
  }
}

export class ConnectionTracker {
  constructor(fpId = 0, maxConnections = 10000) {
    this.fpId = fpId;
    this.maxConnections = maxConnections;
    this.connections = new Map();
    this.totalSeen = 0;
    this.classifiedCount = 0;
    this.blockedCount = 0;
  }

  getOrCreateConnection(tuple) {
    const hash = tuple.getHash();
    let conn = this.connections.get(hash);

    if (conn) return conn;

    // Check reverse tuple
    const revHash = tuple.reverse().getHash();
    conn = this.connections.get(revHash);
    if (conn) return conn;

    if (this.connections.size >= this.maxConnections) {
      this.evictOldest();
    }

    conn = new Connection(tuple);
    this.connections.set(hash, conn);
    this.totalSeen++;
    return conn;
  }

  updateConnection(conn, packetSize, isOutbound) {
    if (!conn) return;
    conn.lastSeen = Date.now();
    if (isOutbound) {
      conn.packetsOut++;
      conn.bytesOut += packetSize;
    } else {
      conn.packetsIn++;
      conn.bytesIn += packetSize;
    }
  }

  classifyConnection(conn, app, sni) {
    if (!conn) return;
    if (conn.state !== ConnectionState.CLASSIFIED) {
      conn.appType = app;
      conn.sni = sni || "";
      conn.state = ConnectionState.CLASSIFIED;
      this.classifiedCount++;
    }
  }

  blockConnection(conn) {
    if (!conn) return;
    conn.state = ConnectionState.BLOCKED;
    conn.action = PacketAction.DROP;
    this.blockedCount++;
  }

  evictOldest() {
    let oldestHash = null;
    let oldestTime = Infinity;

    for (const [hash, conn] of this.connections.entries()) {
      if (conn.lastSeen < oldestTime) {
        oldestTime = conn.lastSeen;
        oldestHash = hash;
      }
    }

    if (oldestHash) {
      this.connections.delete(oldestHash);
    }
  }

  getStats() {
    return {
      activeConnections: this.connections.size,
      totalConnectionsSeen: this.totalSeen,
      classifiedConnections: this.classifiedCount,
      blockedConnections: this.blockedCount
    };
  }
}

export class GlobalConnectionTable {
  constructor() {
    this.trackers = [];
  }

  registerTracker(tracker) {
    this.trackers.push(tracker);
  }

  getGlobalStats() {
    const stats = {
      totalActiveConnections: 0,
      totalConnectionsSeen: 0,
      appDistribution: {},
      topDomains: []
    };

    const domainCounts = new Map();

    for (const tracker of this.trackers) {
      const ts = tracker.getStats();
      stats.totalActiveConnections += ts.activeConnections;
      stats.totalConnectionsSeen += ts.totalConnectionsSeen;

      for (const conn of tracker.connections.values()) {
        stats.appDistribution[conn.appType] = (stats.appDistribution[conn.appType] || 0) + 1;
        if (conn.sni) {
          domainCounts.set(conn.sni, (domainCounts.get(conn.sni) || 0) + 1);
        }
      }
    }

    const sortedDomains = Array.from(domainCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20);

    stats.topDomains = sortedDomains;
    return stats;
  }

  generateReport() {
    const stats = this.getGlobalStats();
    let report = "\n" + "=".repeat(60) + "\n";
    report += "          CONNECTION STATISTICS REPORT\n";
    report += "=".repeat(60) + "\n";
    report += `Active Connections:     ${stats.totalActiveConnections.toString().padStart(10)}\n`;
    report += `Total Connections Seen: ${stats.totalConnectionsSeen.toString().padStart(10)}\n`;
    report += "-".repeat(60) + "\n";
    report += "               APPLICATION BREAKDOWN\n";
    report += "-".repeat(60) + "\n";

    let total = 0;
    for (const count of Object.values(stats.appDistribution)) total += count;

    const sortedApps = Object.entries(stats.appDistribution)
      .sort((a, b) => b[1] - a[1]);

    for (const [appType, count] of sortedApps) {
      const pct = total > 0 ? (100 * count / total).toFixed(1) : "0.0";
      const name = AppTypeNames[appType] || `Type ${appType}`;
      report += `${name.padEnd(20)} ${count.toString().padStart(10)} (${pct.padStart(5)}%)\n`;
    }

    if (stats.topDomains.length > 0) {
      report += "-".repeat(60) + "\n";
      report += "                  TOP DOMAINS\n";
      report += "-".repeat(60) + "\n";
      for (const [domain, count] of stats.topDomains) {
        report += `${domain.padEnd(40)} ${count.toString().padStart(10)}\n`;
      }
    }
    report += "=".repeat(60) + "\n";
    return report;
  }
}

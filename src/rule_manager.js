import fs from 'fs';
import { AppTypeNames } from './types.js';

export class RuleManager {
  constructor() {
    this.blockedIps = new Set();
    this.blockedApps = new Set();
    this.blockedDomains = new Set();
    this.domainPatterns = [];
    this.blockedPorts = new Set();
  }

  static ipToString(ip) {
    return `${(ip >> 0) & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}`;
  }

  static parseIP(ipStr) {
    const parts = ipStr.split('.').map(Number);
    if (parts.length !== 4) return 0;
    return (parts[0] << 0) | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
  }

  blockIP(ip) {
    const ipNum = typeof ip === 'string' ? RuleManager.parseIP(ip) : ip;
    this.blockedIps.add(ipNum);
    console.log(`[RuleManager] Blocked IP: ${RuleManager.ipToString(ipNum)}`);
  }

  unblockIP(ip) {
    const ipNum = typeof ip === 'string' ? RuleManager.parseIP(ip) : ip;
    this.blockedIps.delete(ipNum);
  }

  isIPBlocked(ip) {
    return this.blockedIps.has(ip);
  }

  blockApp(app) {
    this.blockedApps.add(app);
    console.log(`[RuleManager] Blocked app: ${AppTypeNames[app] || app}`);
  }

  unblockApp(app) {
    this.blockedApps.delete(app);
  }

  isAppBlocked(app) {
    return this.blockedApps.has(app);
  }

  blockDomain(domain) {
    if (domain.includes('*')) {
      this.domainPatterns.push(domain.toLowerCase());
    } else {
      this.blockedDomains.add(domain.toLowerCase());
    }
    console.log(`[RuleManager] Blocked domain: ${domain}`);
  }

  isDomainBlocked(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
    if (this.blockedDomains.has(d)) return true;

    for (const pattern of this.domainPatterns) {
      if (this.domainMatchesPattern(d, pattern)) return true;
    }
    return false;
  }

  domainMatchesPattern(domain, pattern) {
    if (pattern.startsWith('*.')) {
      const suffix = pattern.substring(1);
      if (domain.endsWith(suffix)) return true;
      if (domain === pattern.substring(2)) return true;
    }
    return false;
  }

  blockPort(port) {
    this.blockedPorts.add(port);
    console.log(`[RuleManager] Blocked port: ${port}`);
  }

  isPortBlocked(port) {
    return this.blockedPorts.has(port);
  }

  shouldBlock(srcIp, dstPort, app, domain) {
    if (this.isIPBlocked(srcIp)) return { type: 'IP', value: RuleManager.ipToString(srcIp) };
    if (this.isPortBlocked(dstPort)) return { type: 'PORT', value: dstPort.toString() };
    if (this.isAppBlocked(app)) return { type: 'APP', value: AppTypeNames[app] || app };
    if (domain && this.isDomainBlocked(domain)) return { type: 'DOMAIN', value: domain };
    return null;
  }

  loadRules(filename) {
    try {
      if (!fs.existsSync(filename)) return false;
      const content = fs.readFileSync(filename, 'utf-8');
      const lines = content.split('\n');
      let section = '';

      for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;

        if (line.startsWith('[') && line.endsWith(']')) {
          section = line.substring(1, line.length - 1);
          continue;
        }

        switch (section) {
          case 'BLOCKED_IPS':
            this.blockIP(line);
            break;
          case 'BLOCKED_APPS':
            // This assumes app names in the file match our internal names or numbers
            // For simplicity, we'll need a way to map them. 
            // The C++ version might have a helper for this.
            break;
          case 'BLOCKED_DOMAINS':
            this.blockDomain(line);
            break;
          case 'BLOCKED_PORTS':
            this.blockPort(parseInt(line));
            break;
        }
      }
      return true;
    } catch (err) {
      console.error(`Error loading rules: ${err.message}`);
      return false;
    }
  }
}

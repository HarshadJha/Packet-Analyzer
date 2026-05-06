/**
 * 
 * Utilities for Deep Packet Inspection (DPI)
 */

export class SNIExtractor {
  static CONTENT_TYPE_HANDSHAKE = 0x16;
  static HANDSHAKE_CLIENT_HELLO = 0x01;
  static EXTENSION_SNI = 0x0000;
  static SNI_TYPE_HOSTNAME = 0x00;

  static isTLSClientHello(payload) {
    if (!payload || payload.length < 9) return false;
    if (payload[0] !== this.CONTENT_TYPE_HANDSHAKE) return false;
    
    const version = payload.readUInt16BE(1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    const recordLength = payload.readUInt16BE(3);
    if (recordLength > payload.length - 5) return false;
    
    if (payload[5] !== this.HANDSHAKE_CLIENT_HELLO) return false;
    
    return true;
  }

  static extract(payload) {
    if (!this.isTLSClientHello(payload)) return null;

    let offset = 5; // Skip TLS record header
    // const handshakeLength = (payload[offset+1] << 16) | (payload[offset+2] << 8) | payload[offset+3];
    offset += 4; // Skip handshake header
    offset += 2; // Skip client version
    offset += 32; // Skip random

    if (offset >= payload.length) return null;
    const sessionIdLength = payload[offset];
    offset += 1 + sessionIdLength;

    if (offset + 2 > payload.length) return null;
    const cipherSuitesLength = payload.readUInt16BE(offset);
    offset += 2 + cipherSuitesLength;

    if (offset >= payload.length) return null;
    const compressionMethodsLength = payload[offset];
    offset += 1 + compressionMethodsLength;

    if (offset + 2 > payload.length) return null;
    const extensionsLength = payload.readUInt16BE(offset);
    offset += 2;

    const extensionsEnd = Math.min(offset + extensionsLength, payload.length);

    while (offset + 4 <= extensionsEnd) {
      const extensionType = payload.readUInt16BE(offset);
      const extensionLength = payload.readUInt16BE(offset + 2);
      offset += 4;

      if (offset + extensionLength > extensionsEnd) break;

      if (extensionType === this.EXTENSION_SNI) {
        if (extensionLength < 5) break;
        const sniListLength = payload.readUInt16BE(offset);
        if (sniListLength < 3) break;

        const sniType = payload[offset + 2];
        const sniLength = payload.readUInt16BE(offset + 3);

        if (sniType === this.SNI_TYPE_HOSTNAME && sniLength <= extensionLength - 5) {
          return payload.slice(offset + 5, offset + 5 + sniLength).toString();
        }
        break;
      }
      offset += extensionLength;
    }
    return null;
  }
}

export class HTTPHostExtractor {
  static isHTTPRequest(payload) {
    if (!payload || payload.length < 4) return false;
    const methods = ["GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"];
    const start = payload.slice(0, 4).toString();
    return methods.includes(start);
  }

  static extract(payload) {
    if (!this.isHTTPRequest(payload)) return null;

    const content = payload.toString();
    const match = content.match(/Host:\s*([^\r\n]+)/i);
    if (match) {
      let host = match[1].trim();
      const colonIndex = host.indexOf(':');
      if (colonIndex !== -1) {
        host = host.substring(0, colonIndex);
      }
      return host;
    }
    return null;
  }
}

export class DNSExtractor {
  static isDNSQuery(payload) {
    if (!payload || payload.length < 12) return false;
    const flags = payload[2];
    if (flags & 0x80) return false; // Response
    const qdcount = payload.readUInt16BE(4);
    return qdcount > 0;
  }

  static extractQuery(payload) {
    if (!this.isDNSQuery(payload)) return null;

    let offset = 12;
    const labels = [];
    while (offset < payload.length) {
      const len = payload[offset];
      if (len === 0) break;
      if (len > 63) break; // Compression or invalid
      offset++;
      if (offset + len > payload.length) break;
      labels.push(payload.slice(offset, offset + len).toString());
      offset += len;
    }
    return labels.length > 0 ? labels.join('.') : null;
  }
}

export function sniToAppType(sni, AppType) {
  if (!sni) return AppType.UNKNOWN;
  const s = sni.toLowerCase();

  // YouTube (check before Google)
  if (s.includes("youtube") || s.includes("ytimg") || s.includes("youtu.be") || s.includes("yt3.ggpht")) {
    return AppType.YOUTUBE;
  }
  
  // Google
  if (s.includes("google") || s.includes("gstatic") || s.includes("googleapis") || s.includes("ggpht") || s.includes("gvt1")) {
    return AppType.GOOGLE;
  }
  
  // Facebook
  if (s.includes("facebook") || s.includes("fbcdn") || s.includes("fb.com") || s.includes("fbsbx") || s.includes("meta.com")) {
    return AppType.FACEBOOK;
  }
  
  // Instagram
  if (s.includes("instagram") || s.includes("cdninstagram")) {
    return AppType.INSTAGRAM;
  }
  
  // WhatsApp
  if (s.includes("whatsapp") || s.includes("wa.me")) {
    return AppType.WHATSAPP;
  }
  
  // Twitter/X
  if (s.includes("twitter") || s.includes("twimg") || s.includes("x.com") || s.includes("t.co")) {
    return AppType.TWITTER;
  }
  
  // Netflix
  if (s.includes("netflix") || s.includes("nflxvideo") || s.includes("nflximg")) {
    return AppType.NETFLIX;
  }
  
  // Amazon
  if (s.includes("amazon") || s.includes("amazonaws") || s.includes("cloudfront") || s.includes("aws")) {
    return AppType.AMAZON;
  }
  
  // Microsoft
  if (s.includes("microsoft") || s.includes("msn.com") || s.includes("office") || s.includes("azure") || s.includes("live.com") || s.includes("outlook") || s.includes("bing")) {
    return AppType.MICROSOFT;
  }
  
  // Apple
  if (s.includes("apple") || s.includes("icloud") || s.includes("mzstatic") || s.includes("itunes")) {
    return AppType.APPLE;
  }
  
  // Telegram
  if (s.includes("telegram") || s.includes("t.me")) {
    return AppType.TELEGRAM;
  }
  
  // TikTok
  if (s.includes("tiktok") || s.includes("tiktokcdn") || s.includes("musical.ly") || s.includes("bytedance")) {
    return AppType.TIKTOK;
  }
  
  // Spotify
  if (s.includes("spotify") || s.includes("scdn.co")) {
    return AppType.SPOTIFY;
  }
  
  // Zoom
  if (s.includes("zoom")) {
    return AppType.ZOOM;
  }
  
  // Discord
  if (s.includes("discord") || s.includes("discordapp")) {
    return AppType.DISCORD;
  }
  
  // GitHub
  if (s.includes("github") || s.includes("githubusercontent")) {
    return AppType.GITHUB;
  }
  
  // Cloudflare
  if (s.includes("cloudflare") || s.includes("cf-")) {
    return AppType.CLOUDFLARE;
  }
  
  return AppType.HTTPS;
}

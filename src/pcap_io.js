import fs from 'fs';
import { open } from 'fs/promises';

/**
 * PCAP Global Header (24 bytes)
 */
export class PcapGlobalHeader {
  constructor() {
    this.magicNumber = 0xa1b2c3d4;
    this.versionMajor = 2;
    this.versionMinor = 4;
    this.thiszone = 0;
    this.sigfigs = 0;
    this.snaplen = 65535;
    this.network = 1; // Ethernet
  }

  static fromBuffer(buffer, swap = false) {
    const header = new PcapGlobalHeader();
    if (swap) {
      header.magicNumber = buffer.readUInt32BE(0);
      header.versionMajor = buffer.readUInt16BE(4);
      header.versionMinor = buffer.readUInt16BE(6);
      header.thiszone = buffer.readInt32BE(8);
      header.sigfigs = buffer.readUInt32BE(12);
      header.snaplen = buffer.readUInt32BE(16);
      header.network = buffer.readUInt32BE(20);
    } else {
      header.magicNumber = buffer.readUInt32LE(0);
      header.versionMajor = buffer.readUInt16LE(4);
      header.versionMinor = buffer.readUInt16LE(6);
      header.thiszone = buffer.readInt32LE(8);
      header.sigfigs = buffer.readUInt32LE(12);
      header.snaplen = buffer.readUInt32LE(16);
      header.network = buffer.readUInt32LE(20);
    }
    return header;
  }

  toBuffer() {
    const buffer = Buffer.alloc(24);
    buffer.writeUInt32LE(this.magicNumber, 0);
    buffer.writeUInt16LE(this.versionMajor, 4);
    buffer.writeUInt16LE(this.versionMinor, 6);
    buffer.writeInt32LE(this.thiszone, 8);
    buffer.writeUInt32LE(this.sigfigs, 12);
    buffer.writeUInt32LE(this.snaplen, 16);
    buffer.writeUInt32LE(this.network, 20);
    return buffer;
  }
}

/**
 * PCAP Packet Header (16 bytes)
 */
export class PcapPacketHeader {
  constructor(ts_sec = 0, ts_usec = 0, incl_len = 0, orig_len = 0) {
    this.ts_sec = ts_sec;
    this.ts_usec = ts_usec;
    this.incl_len = incl_len;
    this.orig_len = orig_len;
  }

  static fromBuffer(buffer, swap = false) {
    if (swap) {
      return new PcapPacketHeader(
        buffer.readUInt32BE(0),
        buffer.readUInt32BE(4),
        buffer.readUInt32BE(8),
        buffer.readUInt32BE(12)
      );
    } else {
      return new PcapPacketHeader(
        buffer.readUInt32LE(0),
        buffer.readUInt32LE(4),
        buffer.readUInt32LE(8),
        buffer.readUInt32LE(12)
      );
    }
  }

  toBuffer() {
    const buffer = Buffer.alloc(16);
    buffer.writeUInt32LE(this.ts_sec, 0);
    buffer.writeUInt32LE(this.ts_usec, 4);
    buffer.writeUInt32LE(this.incl_len, 8);
    buffer.writeUInt32LE(this.orig_len, 12);
    return buffer;
  }
}

/**
 * PcapReader to read PCAP files asynchronously
 */
export class PcapReader {
  constructor() {
    this.handle = null;
    this.globalHeader = null;
    this.swap = false;
    this.pos = 0;
  }

  async open(filename) {
    await this.close();
    try {
      this.handle = await open(filename, 'r');
      const { buffer, bytesRead } = await this.handle.read(Buffer.alloc(24), 0, 24, 0);
      
      if (bytesRead < 24) {
        throw new Error('Could not read PCAP global header');
      }

      const magic = buffer.readUInt32LE(0);
      if (magic === 0xa1b2c3d4) {
        this.swap = false;
      } else if (magic === 0xd4c3b2a1) {
        this.swap = true;
      } else {
        throw new Error('Invalid PCAP magic number: 0x' + magic.toString(16));
      }

      this.globalHeader = PcapGlobalHeader.fromBuffer(buffer, this.swap);
      this.pos = 24;
      return true;
    } catch (err) {
      console.error(`[PcapReader] Error opening ${filename}: ${err.message}`);
      await this.close();
      return false;
    }
  }

  async close() {
    if (this.handle) {
      await this.handle.close();
      this.handle = null;
    }
  }

  async readNextPacket() {
    if (!this.handle) return null;

    try {
      const headerBuf = Buffer.alloc(16);
      const { bytesRead: headerBytesRead } = await this.handle.read(headerBuf, 0, 16, this.pos);
      
      if (headerBytesRead < 16) return null;
      this.pos += 16;

      const header = PcapPacketHeader.fromBuffer(headerBuf, this.swap);
      if (header.incl_len > 65535) {
        throw new Error('Invalid packet length: ' + header.incl_len);
      }

      const data = Buffer.alloc(header.incl_len);
      const { bytesRead: dataBytesRead } = await this.handle.read(data, 0, header.incl_len, this.pos);
      
      if (dataBytesRead < header.incl_len) {
        throw new Error('Could not read packet data');
      }
      this.pos += header.incl_len;

      return {
        header,
        data
      };
    } catch (err) {
      console.error(`[PcapReader] Error reading packet: ${err.message}`);
      return null;
    }
  }
}

/**
 * PcapWriter to write PCAP files using streams for high performance
 */
export class PcapWriter {
  constructor() {
    this.stream = null;
  }

  async open(filename, globalHeader = new PcapGlobalHeader()) {
    await this.close();
    try {
      this.stream = fs.createWriteStream(filename);
      
      return new Promise((resolve, reject) => {
        const canWrite = this.stream.write(globalHeader.toBuffer());
        if (canWrite) {
          resolve(true);
        } else {
          this.stream.once('drain', () => resolve(true));
        }
        this.stream.once('error', (err) => {
          console.error(`[PcapWriter] Error opening ${filename}: ${err.message}`);
          resolve(false);
        });
      });
    } catch (err) {
      console.error(`[PcapWriter] Error opening ${filename}: ${err.message}`);
      return false;
    }
  }

  async close() {
    if (this.stream) {
      return new Promise((resolve) => {
        this.stream.end(() => {
          this.stream = null;
          resolve();
        });
      });
    }
  }

  async writePacket(header, data) {
    if (!this.stream) return false;
    
    return new Promise((resolve) => {
      const headerSuccess = this.stream.write(header.toBuffer());
      const dataSuccess = this.stream.write(data);
      
      if (headerSuccess && dataSuccess) {
        resolve(true);
      } else {
        this.stream.once('drain', () => resolve(true));
      }
    });
  }
}


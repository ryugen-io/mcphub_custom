import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const ALGORITHM = 'aes-256-gcm';
const KEY_FILE = 'keys.encrypted';

export class KeyManager {
  private static instance: KeyManager;
  private masterKey: string;
  private keys: Record<string, string> = {};
  private keyFilePath: string;

  private constructor() {
    this.keyFilePath = path.join(process.cwd(), KEY_FILE);
    this.masterKey = this.getMasterKey();
    this.loadKeys();
  }

  static getInstance(): KeyManager {
    if (!KeyManager.instance) {
      KeyManager.instance = new KeyManager();
    }
    return KeyManager.instance;
  }

  private getMasterKey(): string {
    // Try environment variable first (for production)
    if (process.env.MCPHUB_MASTER_KEY) {
      return process.env.MCPHUB_MASTER_KEY;
    }

    // Fallback: generate from machine-specific data
    const hostname = require('os').hostname();
    const platform = process.platform;
    const arch = process.arch;
    
    return crypto
      .createHash('sha256')
      .update(`${hostname}-${platform}-${arch}-mcphub`)
      .digest('hex');
  }

  private encrypt(text: string): { encrypted: string; iv: string; tag: string } {
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(this.masterKey, 'salt', 32);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex')
    };
  }

  private decrypt(encryptedData: { encrypted: string; iv: string; tag: string }): string {
    const key = crypto.scryptSync(this.masterKey, 'salt', 32);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(encryptedData.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  private loadKeys(): void {
    try {
      if (fs.existsSync(this.keyFilePath)) {
        const encryptedContent = fs.readFileSync(this.keyFilePath, 'utf8');
        const encryptedData = JSON.parse(encryptedContent);
        const decryptedContent = this.decrypt(encryptedData);
        this.keys = JSON.parse(decryptedContent);
      }
    } catch (error) {
      console.warn('Could not load encrypted keys:', error);
      this.keys = {};
    }
  }

  private saveKeys(): void {
    try {
      const keysJson = JSON.stringify(this.keys, null, 2);
      const encryptedData = this.encrypt(keysJson);
      fs.writeFileSync(this.keyFilePath, JSON.stringify(encryptedData, null, 2));
    } catch (error) {
      console.error('Could not save encrypted keys:', error);
    }
  }

  setKey(name: string, value: string): void {
    this.keys[name] = value;
    this.saveKeys();
  }

  getKey(name: string): string | undefined {
    return this.keys[name];
  }

  hasKey(name: string): boolean {
    return name in this.keys;
  }

  deleteKey(name: string): void {
    delete this.keys[name];
    this.saveKeys();
  }

  listKeys(): string[] {
    return Object.keys(this.keys);
  }

  // Initialize with default keys if they don't exist
  initializeDefaultKeys(): void {
    // Check if keys need to be initialized from environment
    const envKeys = ['SVGMAKER_API_KEY', 'POSTMAN_API_KEY'];
    
    let hasChanges = false;
    for (const key of envKeys) {
      if (!this.hasKey(key) && process.env[key]) {
        this.keys[key] = process.env[key]!;
        hasChanges = true;
        console.log(`Initialized encrypted key: ${key}`);
      }
    }

    if (hasChanges) {
      this.saveKeys();
    }
  }
}

// Export singleton instance
export const keyManager = KeyManager.getInstance();
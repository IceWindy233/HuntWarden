import { safeStorage } from "electron";
import type { SecretCipher } from "../credentials/credential-store.js";

export class ElectronSafeStorageCipher implements SecretCipher {
  async encrypt(plainText: string): Promise<string> {
    const encrypted = await safeStorage.encryptStringAsync(plainText);
    return encrypted.toString("base64");
  }

  async decrypt(cipherText: string): Promise<string> {
    const decrypted = await safeStorage.decryptStringAsync(Buffer.from(cipherText, "base64"));
    return decrypted.result;
  }

  async isSecure(): Promise<boolean> {
    const available = await safeStorage.isAsyncEncryptionAvailable();
    if (!available) return false;
    return process.platform !== "linux" || safeStorage.getSelectedStorageBackend() !== "basic_text";
  }

  async backend(): Promise<string> {
    if (process.platform === "linux") return safeStorage.getSelectedStorageBackend();
    return process.platform === "darwin" ? "macOS Keychain" : process.platform === "win32" ? "Windows DPAPI" : process.platform;
  }
}

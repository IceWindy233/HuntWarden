import { isAbsolute } from "node:path";
import { InvalidArgumentError } from "../common/errors.js";
import type { TargetConfig } from "./types.js";

const USERNAME = /^[A-Za-z_][A-Za-z0-9_-]{0,31}$/;
const HOST = /^[^\s\0]{1,253}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{20,}$/;

export function validateTargetConfig(target: TargetConfig): void {
  if (!HOST.test(target.host)) throw new InvalidArgumentError("目标主机格式无效");
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65_535) throw new InvalidArgumentError("SSH 端口无效");
  if (!USERNAME.test(target.username)) throw new InvalidArgumentError("SSH 用户名格式无效");
  if (!FINGERPRINT.test(target.hostFingerprint)) throw new InvalidArgumentError("主机指纹必须是 OpenSSH SHA256 格式");
  if (!isAbsolute(target.privateKeyPath) || !isAbsolute(target.knownHostsPath)) throw new InvalidArgumentError("SSH 密钥与 known_hosts 必须使用绝对路径");
}

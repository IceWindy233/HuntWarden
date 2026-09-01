import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { TargetConfig } from "../../src/domain/types.js";
import type { ForensicVerb, MaintenanceVerb } from "../../src/executor/protocol-v2-executor.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import type { WireCost, WireRequest, WireSuccess } from "../../src/protocol-v2/types.js";

const stateDir = resolve("labs/.lab-state");

export async function dockerV2Remote(port: number): Promise<DockerV2Remote> {
  const knownHostsPath = resolve(stateDir, "known_hosts");
  const knownHosts = await readFile(knownHostsPath, "utf8");
  const fingerprint = knownHosts.match(new RegExp(`# (SHA256:[A-Za-z0-9+/]+) port=${port}`))?.[1];
  if (!fingerprint) throw new Error(`known_hosts 缺少 ${port} 的指纹`);
  const target: TargetConfig = { host: "127.0.0.1", port, username: "secagent", hostFingerprint: fingerprint, privateKeyPath: resolve(stateDir, "id_ed25519"), knownHostsPath };
  return new DockerV2Remote(new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 60_000));
}

export class DockerV2Remote {
  private sequence = 0;
  constructor(readonly executor: SSHExecutor) {}
  async close(): Promise<void> { await this.executor.close(); }

  async invoke(verb: ForensicVerb, params: Record<string, unknown>, estimate?: WireCost): Promise<WireSuccess> {
    this.sequence += 1; const requestId = `DOCKER-V2-${this.sequence}`;
    const cost = estimate ?? { remoteCalls: 1, nodes: 500, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: verb === "probe" ? 1 : 0 };
    const request: WireRequest = { protocolVersion: 2, requestId, epochId: "EPOCH-DOCKER-V2", deadlineMs: 60_000, reservation: { reservationId: `BRES-${requestId}`, estimate: cost }, params };
    const response = await this.executor.invokeV2(verb, request);
    if (response.status === "ERROR") throw new Error(`${response.error.code}: ${response.error.message}`);
    return response;
  }

  async maintenance(verb: MaintenanceVerb, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.sequence += 1; const requestId = `DOCKER-V2-M-${this.sequence}`;
    const request: WireRequest = { protocolVersion: 2, requestId, epochId: "EPOCH-DOCKER-V2", deadlineMs: 60_000, reservation: { reservationId: `BRES-${requestId}`, estimate: { remoteCalls: 1, nodes: 1, bytes: 1024, wallTimeMs: 60_000, probeCalls: 0 } }, params };
    return await this.executor.invokeMaintenanceV2(verb, request);
  }

  async enumerate(namespace: string, fields: string[], extra: Record<string, unknown> = {}): Promise<WireSuccess["objects"]> {
    const objects: WireSuccess["objects"] = []; let cursor: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const response = await this.invoke("enumerate", { namespace, fields, limit: 500, ...extra, ...(cursor ? { cursor } : {}) });
      objects.push(...response.objects); cursor = response.cursor;
      if (!cursor) return objects;
    }
    throw new Error(`${namespace} enumerate 超过测试分页上限`);
  }
}

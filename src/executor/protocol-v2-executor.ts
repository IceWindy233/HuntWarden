import type { ArtifactTransferResult, RemoteArtifact } from "./artifacts.js";
import type { HelperCapabilitiesV2, WireRequest, WireResponse } from "../protocol-v2/types.js";

export const FORENSIC_VERBS = ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"] as const;
export type ForensicVerb = typeof FORENSIC_VERBS[number];
export const MAINTENANCE_VERBS = ["scope_resolve", "artifact_release", "get_action_receipt", "quarantine_file", "disable_account"] as const;
export type MaintenanceVerb = typeof MAINTENANCE_VERBS[number];

export interface ProtocolV2Executor {
  getCapabilitiesV2(signal?: AbortSignal): Promise<HelperCapabilitiesV2>;
  invokeV2(verb: ForensicVerb, request: WireRequest, signal?: AbortSignal): Promise<WireResponse>;
  invokeMaintenanceV2(verb: MaintenanceVerb, request: WireRequest, signal?: AbortSignal): Promise<Record<string, unknown>>;
  downloadArtifact(artifact: RemoteArtifact, onChunk: (chunk: Buffer) => void | Promise<void>, signal?: AbortSignal, timeoutMs?: number): Promise<ArtifactTransferResult>;
  close(): Promise<void>;
}

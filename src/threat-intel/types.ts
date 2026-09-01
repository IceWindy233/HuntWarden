export const DBAPP_THREAT_INTEL_SOURCE = "安恒威胁情报 (DBAPP Threat Intelligence)" as const;

export type ThreatIntelIocType = "ip" | "domain" | "file";
export type ThreatIntelRiskLevel = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export interface ThreatIntelVerdict {
  ioc: string;
  iocType: ThreatIntelIocType;
  malicious: boolean | null;
  riskLevel: ThreatIntelRiskLevel;
  confidence: number | null;
  threatTypes: string[];
  apt: boolean | null;
  hackerGroups: string[];
  attackEvents: string[];
  malwareFamilies: string[];
  description?: string;
  cached: boolean;
  source: typeof DBAPP_THREAT_INTEL_SOURCE;
  reportUrl?: string;
}

export interface ThreatIntelBatchResult {
  provider: "dbapp-ti";
  source: typeof DBAPP_THREAT_INTEL_SOURCE;
  requestId?: string;
  queriedAt: string;
  verdicts: ThreatIntelVerdict[];
  warnings: string[];
}

export interface ThreatIntelClient {
  compromiseDetection(iocs: readonly string[], signal?: AbortSignal): Promise<ThreatIntelBatchResult>;
  batchFileInfo(hashes: readonly string[], signal?: AbortSignal): Promise<ThreatIntelBatchResult>;
}

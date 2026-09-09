import { lookup } from "node:dns/promises";

export type ProviderResolutionSource = "SYSTEM" | "DNS_OVER_HTTPS_PROXY_FALLBACK";

export interface ProviderEndpointResolution {
  addresses: string[];
  source: ProviderResolutionSource;
  systemAddresses: string[];
}

type QualificationLookup = (
  hostname: string,
  options: { all: true; verbatim: true },
) => Promise<Array<{ address: string }>>;

interface DnsJsonAnswer {
  type?: unknown;
  data?: unknown;
}

interface DnsJsonResponse {
  Status?: unknown;
  Answer?: unknown;
}

function uniqueSorted(addresses: readonly string[]): string[] {
  return [...new Set(addresses.map((address) => address.toLowerCase()))].sort();
}

export function isSyntheticProxyAddress(address: string): boolean {
  const parts = address.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((part) => Number(part));
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return octets[0] === 198 && (octets[1] === 18 || octets[1] === 19);
}

async function resolveDnsJson(hostname: string, recordType: "A" | "AAAA", fetchImpl: typeof fetch): Promise<string[]> {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.searchParams.set("name", hostname);
  url.searchParams.set("type", recordType);
  const response = await fetchImpl(url, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`DNS over HTTPS 查询失败: HTTP ${response.status}`);
  const body = await response.json() as DnsJsonResponse;
  if (body.Status !== 0) throw new Error(`DNS over HTTPS 查询失败: DNS status ${String(body.Status)}`);
  if (!Array.isArray(body.Answer)) return [];
  const expectedType = recordType === "A" ? 1 : 28;
  return body.Answer.flatMap((answer): string[] => {
    if (typeof answer !== "object" || answer === null) return [];
    const typed = answer as DnsJsonAnswer;
    return typed.type === expectedType && typeof typed.data === "string" ? [typed.data] : [];
  });
}

/**
 * 透明代理常用 RFC 2544 基准网段作为 fake-IP。只有系统解析结果全部属于该网段时，
 * 才通过带 TLS 身份校验的 DoH 获取可审计的公网解析；普通私网或混合解析继续原样返回并由资格门禁拒绝。
 */
export async function resolveProviderEndpoint(
  endpoint: string,
  dependencies: {
    lookup?: QualificationLookup;
    fetch?: typeof fetch;
  } = {},
): Promise<ProviderEndpointResolution> {
  const hostname = new URL(endpoint).hostname.replace(/^\[|\]$/g, "");
  const lookupImpl: QualificationLookup = dependencies.lookup ?? lookup;
  const fetchImpl = dependencies.fetch ?? fetch;
  const systemAddresses = uniqueSorted((await lookupImpl(hostname, { all: true, verbatim: true })).map((item) => item.address));
  if (systemAddresses.length === 0 || !systemAddresses.every(isSyntheticProxyAddress)) {
    return { addresses: systemAddresses, source: "SYSTEM", systemAddresses };
  }
  const resolved = uniqueSorted((await Promise.all([
    resolveDnsJson(hostname, "A", fetchImpl),
    resolveDnsJson(hostname, "AAAA", fetchImpl),
  ])).flat());
  if (resolved.length === 0) throw new Error("DNS over HTTPS 未返回 Provider 地址");
  return { addresses: resolved, source: "DNS_OVER_HTTPS_PROXY_FALLBACK", systemAddresses };
}

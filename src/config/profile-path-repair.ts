import { access } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import type { AppConfig } from "./schema.js";

export interface ProfilePathRepairOptions {
  appPath: string;
  currentUserData: string;
  labStateDir?: string;
}

async function usableLabStateDir(path: string): Promise<boolean> {
  try {
    await Promise.all([access(join(path, "id_ed25519")), access(join(path, "known_hosts"))]);
    return true;
  } catch {
    return false;
  }
}

export async function findLocalLabStateDir(input: { appPath: string; cwd: string; explicit?: string }): Promise<string | undefined> {
  const candidates: string[] = [];
  if (input.explicit && isAbsolute(input.explicit)) candidates.push(resolve(input.explicit));
  for (const start of [input.cwd, input.appPath]) {
    let current = resolve(start);
    for (let depth = 0; depth < 10; depth += 1) {
      candidates.push(join(current, "labs", ".lab-state"));
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  for (const candidate of [...new Set(candidates)]) if (await usableLabStateDir(candidate)) return candidate;
  return undefined;
}

function containsOldBrand(path: string): boolean {
  return path.includes(`${sep}SecHostAgent${sep}`) || path.includes(`${sep}sechost-agent${sep}`)
    || path.includes("SecHostAgent.app/Contents/Resources/app.asar");
}

function isPackagedLabPath(path: string): boolean {
  return path.includes(`${sep}Contents${sep}Resources${sep}app.asar${sep}labs${sep}.lab-state${sep}`);
}

export function repairProfilePaths(config: AppConfig, options: ProfilePathRepairOptions): boolean {
  let changed = false;
  const replace = (current: string, next: string, apply: (value: string) => void): void => {
    if (current === next) return;
    apply(next);
    changed = true;
  };

  if (containsOldBrand(config.storage.baseDir)) {
    replace(config.storage.baseDir, join(options.currentUserData, "runtime"), (value) => { config.storage.baseDir = value; });
  }
  if (config.agent.promptVersion === "sechost-agent-v1") {
    config.agent.promptVersion = "huntwarden-agent-v1";
    changed = true;
  }
  if (config.executor.helperPath === "/usr/local/libexec/sechost-agent-helper") {
    config.executor.helperPath = "/usr/local/libexec/huntwarden-helper";
    changed = true;
  }
  if (config.remediation.quarantineRoot === "/var/lib/sechost-agent/quarantine") {
    config.remediation.quarantineRoot = "/var/lib/huntwarden/quarantine";
    changed = true;
  }
  if (config.model.source === "custom" && config.model.authentication.type === "api-key-env" && config.model.authentication.apiKeyEnv === "SECHOST_LLM_API_KEY") {
    config.model.authentication.apiKeyEnv = "HUNTWARDEN_LLM_API_KEY";
    changed = true;
  }
  if (containsOldBrand(config.webshell.yaraRuleDir)) {
    replace(config.webshell.yaraRuleDir, join(options.appPath, "rules", "yara"), (value) => { config.webshell.yaraRuleDir = value; });
  }
  if (containsOldBrand(config.java.probeJar)) {
    replace(config.java.probeJar, join(options.appPath, "java", "tomcat-probe", "build", "libs", "huntwarden-tomcat-probe.jar"), (value) => { config.java.probeJar = value; });
  }

  if (options.labStateDir) {
    if (containsOldBrand(config.executor.knownHostsPath) || isPackagedLabPath(config.executor.knownHostsPath)) {
      replace(config.executor.knownHostsPath, join(options.labStateDir, "known_hosts"), (value) => { config.executor.knownHostsPath = value; });
    }
    if (containsOldBrand(config.executor.privateKeyPath) || isPackagedLabPath(config.executor.privateKeyPath)) {
      replace(config.executor.privateKeyPath, join(options.labStateDir, "id_ed25519"), (value) => { config.executor.privateKeyPath = value; });
    }
  }
  return changed;
}

export function isInvalidPackagedLabCredentialPath(path: string): boolean {
  return isPackagedLabPath(path);
}

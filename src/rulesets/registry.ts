export const BUILTIN_YARA_RULESETS = Object.freeze({
  "RULESET-WEBSHELL-BUILTIN-2": Object.freeze({
    ruleSetRef: "RULESET-WEBSHELL-BUILTIN-2",
    name: "HuntWarden WebShell Built-in",
    version: "2.0.0",
    trust: "BUILTIN" as const,
    sha256: "6f90570d618fbd00b707148c74cfeddd4cffc1bfb712f1fb8ab397fe077a1660",
  }),
});

export type BuiltinYaraRuleSetRef = keyof typeof BUILTIN_YARA_RULESETS;

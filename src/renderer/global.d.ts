import type { HuntWardenDesktopApi } from "../gui/contracts.js";

declare global {
  interface Window { huntwarden: HuntWardenDesktopApi }
}

export {};

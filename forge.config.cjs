const path = require("node:path");

module.exports = {
  packagerConfig: {
    asar: true,
    executableName: "HuntWarden",
    icon: path.resolve(__dirname, "assets/icon.icns"),
    appBundleId: "com.huntwarden.desktop",
    appCategoryType: "public.app-category.developer-tools",
    ignore: [
      /^\/data($|\/)/,
      /^\/labs($|\/)/,
      /^\/tests($|\/)/,
      /^\/coverage($|\/)/,
      /^\/docs($|\/)/,
      /^\/release($|\/)/,
    ],
  },
  makers: [
    { name: "@electron-forge/maker-zip", platforms: ["darwin", "linux"] },
    { name: "@electron-forge/maker-dmg", config: { format: "ULFO" } },
  ],
};

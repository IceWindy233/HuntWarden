#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "拒绝从非干净工作树生成发布资产。请先提交或移除本地修改。" >&2
  exit 1
fi

version="$(node -p "require('./package.json').version")"
release_dir="$project_root/release/v$version"
mkdir -p "$release_dir"

npm ci
npm run audit:prod
npm run build
npm test
npm run probe:build
npm run make:gui

packaged_asar="$(find "$project_root/out" -path '*/HuntWarden.app/Contents/Resources/app.asar' -print -quit)"
if [[ -z "$packaged_asar" ]]; then
  echo "未找到打包后的 app.asar。" >&2
  exit 1
fi
if npx --no-install asar list "$packaged_asar" | grep -Eq '^/release($|/)'; then
  echo "发布资产目录被递归打入 app.asar；拒绝生成 Release。" >&2
  exit 1
fi

zip_artifact="$project_root/out/make/zip/darwin/arm64/HuntWarden-darwin-arm64-$version.zip"
dmg_artifact="$project_root/out/make/HuntWarden-$version-arm64.dmg"
for artifact in "$zip_artifact" "$dmg_artifact"; do
  if [[ ! -f "$artifact" ]]; then
    echo "未找到当前版本的 Electron Forge 发布资产：$artifact" >&2
    exit 1
  fi
done

# out/make 和 release 可能保留上一个版本的产物，只收集当前版本并清理发布目录中的旧分发包。
find "$release_dir" -maxdepth 1 -type f \( -name '*.zip' -o -name '*.dmg' -o -name 'SHA256SUMS' \) -delete
cp "$zip_artifact" "$dmg_artifact" "$release_dir/"

artifact_count="$(find "$release_dir" -maxdepth 1 -type f \( -name '*.zip' -o -name '*.dmg' \) | wc -l | tr -d ' ')"
if [[ "$artifact_count" != "2" ]]; then
  echo "发布目录应恰好包含当前版本的 zip 和 dmg，实际为 $artifact_count 个。" >&2
  exit 1
fi

(
  cd "$release_dir"
  shasum -a 256 ./*.zip ./*.dmg 2>/dev/null > SHA256SUMS ||
    find . -maxdepth 1 -type f \( -name '*.zip' -o -name '*.dmg' \) -print0 |
      sort -z |
      xargs -0 shasum -a 256 > SHA256SUMS
)

echo "发布资产已生成：$release_dir"
cat "$release_dir/SHA256SUMS"

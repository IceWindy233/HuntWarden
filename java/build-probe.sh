#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd "$(dirname "$0")/tomcat-probe" && pwd)
resolved_javac=$(realpath "$(command -v javac)" 2>/dev/null || command -v javac)
path_java_candidate=$(cd "$(dirname "$resolved_javac")/.." 2>/dev/null && pwd || true)
java_candidates=(
  "${JAVA_HOME:-}"
  "$path_java_candidate"
  "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"
  "/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home"
  "/opt/homebrew/opt/openjdk@24/libexec/openjdk.jdk/Contents/Home"
)

selected_java=""
for candidate in "${java_candidates[@]}"; do
  [[ -n "$candidate" && -x "$candidate/bin/javac" ]] || continue
  version_text=$("$candidate/bin/javac" -version 2>&1)
  version=${version_text#javac }
  major=${version%%.*}
  if [[ "$major" == "1" ]]; then
    remainder=${version#*.}
    major=${remainder%%.*}
  fi
  if [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 17 )); then
    selected_java="$candidate"
    break
  fi
done

if [[ -z "$selected_java" ]]; then
  printf 'Java 17+ JDK is required to build the Tomcat probe.\n' >&2
  exit 1
fi
export JAVA_HOME="$selected_java"
exec "$project_dir/gradlew" -p "$project_dir" --no-daemon --console=plain "$@"

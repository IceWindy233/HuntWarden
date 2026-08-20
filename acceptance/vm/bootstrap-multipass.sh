#!/usr/bin/env bash
set -euo pipefail

# 在本机 Multipass 上准备一台 Ubuntu ARM64 临时 VM，用于 v0.1.0 的真实主机只读验收。
#
# 本脚本只做阶段 0～2 与阶段 3 的环境准备：
#   1. 构建 Tomcat 探针，生成本次验收专用的无交互 SSH 私钥
#   2. 启动 VM，注入公钥
#   3. 经 hypervisor 通道带外读取 Host Key 指纹并生成独立 known_hosts
#   4. 传输仓库并安装 Helper，先在最低依赖下自检，再按需安装完整依赖后复检
#   5. 生成可 source 的环境变量文件，供 `npm run test:acceptance:vm` 使用
#
# 只读冒烟、GUI 完整验收与模板回填仍需人工执行，见 acceptance/vm/README.md。
#
# 安全边界：
#   - Host Key 指纹只经 `multipass exec` 读取，绝不使用 ssh-keyscan。
#     后者是「首次在线观察」，项目安全不变量明令禁止把它当作可信来源。
#   - 私钥、known_hosts 与含真实 IP 的环境变量文件一律写入 ${HOME}/.huntwarden-vm，
#     绝不写入仓库，避免被提交。
#   - 不联网下载任何内容；VM 内的依赖安装使用发行版自带包管理器。

readonly DEFAULT_VM_NAME="hw-vm"
readonly DEFAULT_IMAGE="24.04"
readonly DEFAULT_CPUS="2"
readonly DEFAULT_MEMORY="4G"
readonly DEFAULT_DISK="20G"
readonly VM_USER="ubuntu"
readonly REMOTE_REPO="/home/${VM_USER}/HuntWarden"
readonly PROBE_JAR="java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar"
# 完整依赖：yara 影响 WebShell 批量扫描，auditd 影响执行事件，JDK 影响 Tomcat Attach。
readonly FULL_DEPS=("yara" "auditd" "openjdk-17-jdk-headless")

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
state_dir="${HOME}/.huntwarden-vm"

usage() {
  >&2 cat <<'USAGE'
用法: acceptance/vm/bootstrap-multipass.sh [选项]

  --name <名称>        VM 名称，默认 hw-vm
  --image <镜像>       Multipass 镜像，默认 24.04
  --cpus <数量>        默认 2
  --memory <大小>      默认 4G
  --disk <大小>        默认 20G
  --full-deps          安装 yara/auditd/JDK 后再自检一次（两遍自检是 Gate B 第 4、5 项要求）
  --skip-probe         跳过 npm run probe:build，复用已有产物
  --recreate           先销毁同名 VM 再重建
  --destroy            只销毁同名 VM 与其磁盘，不做其它事
  -h, --help           显示本说明

产物（全部位于 ${HOME}/.huntwarden-vm，不进仓库）：
  operator_ed25519[.pub]   本次验收专用私钥
  known_hosts              带外核验后的 Host Key
  <name>.env               可 source 的验收环境变量
USAGE
  exit 2
}

vm_name="${DEFAULT_VM_NAME}"
image="${DEFAULT_IMAGE}"
cpus="${DEFAULT_CPUS}"
memory="${DEFAULT_MEMORY}"
disk="${DEFAULT_DISK}"
full_deps=0
skip_probe=0
recreate=0
destroy_only=0

while (($# > 0)); do
  case "$1" in
    --name) (($# >= 2)) || usage; vm_name="$2"; shift 2 ;;
    --image) (($# >= 2)) || usage; image="$2"; shift 2 ;;
    --cpus) (($# >= 2)) || usage; cpus="$2"; shift 2 ;;
    --memory) (($# >= 2)) || usage; memory="$2"; shift 2 ;;
    --disk) (($# >= 2)) || usage; disk="$2"; shift 2 ;;
    --full-deps) full_deps=1; shift ;;
    --skip-probe) skip_probe=1; shift ;;
    --recreate) recreate=1; shift ;;
    --destroy) destroy_only=1; shift ;;
    -h|--help) usage ;;
    *) >&2 echo "未知参数: $1"; usage ;;
  esac
done

[[ ${vm_name} =~ ^[a-zA-Z][a-zA-Z0-9-]{0,30}$ ]] || { >&2 echo "VM 名称非法: ${vm_name}"; exit 2; }

step() { printf '\n===== %s =====\n' "$1"; }
fail() { >&2 printf '失败: %s\n' "$1"; exit 1; }

command -v multipass >/dev/null || fail "未找到 multipass，请先执行 brew install --cask multipass"

vm_exists() { multipass info "${vm_name}" >/dev/null 2>&1; }

destroy_vm() {
  if vm_exists; then
    step "销毁 VM ${vm_name}"
    multipass delete "${vm_name}" --purge
    echo "已销毁并清除磁盘。"
  else
    echo "VM ${vm_name} 不存在，无需销毁。"
  fi
}

if ((destroy_only == 1)); then
  destroy_vm
  echo "提示：${state_dir} 下的私钥与环境变量文件未删除，确认不再需要后请自行清理。"
  exit 0
fi

((recreate == 1)) && destroy_vm

# ---------- 阶段 0：本机准备 ----------

step "阶段 0：本机准备"

mkdir -p "${state_dir}"
chmod 700 "${state_dir}"

key_path="${state_dir}/operator_ed25519"
if [[ -f ${key_path} ]]; then
  echo "复用已有验收私钥: ${key_path}"
else
  ssh-keygen -q -t ed25519 -N '' -C "huntwarden-vm-acceptance" -f "${key_path}"
  echo "已生成验收专用私钥: ${key_path}"
fi
chmod 600 "${key_path}"

if ((skip_probe == 1)); then
  echo "按 --skip-probe 跳过探针构建。"
elif [[ -f "${repo_root}/${PROBE_JAR}" ]]; then
  echo "探针已存在，跳过构建: ${PROBE_JAR}"
else
  echo "构建 Tomcat 探针（需要本机 Java 17+）..."
  ( cd "${repo_root}" && npm run --silent probe:build )
fi
if [[ -f "${repo_root}/${PROBE_JAR}" ]]; then
  echo "探针: ${PROBE_JAR}"
else
  echo "警告: 探针不存在，Helper 安装会跳过探针下发，Java 内存马检测在该 VM 上不可用。" >&2
fi

# ---------- 阶段 1：启动 VM 并带外核验 Host Key ----------

step "阶段 1：启动 VM 并带外核验 Host Key"

if vm_exists; then
  echo "VM ${vm_name} 已存在，复用。需要全新环境请加 --recreate。"
  multipass start "${vm_name}" >/dev/null 2>&1 || true
else
  echo "启动 ${image}（cpus=${cpus} memory=${memory} disk=${disk}）..."
  multipass launch "${image}" --name "${vm_name}" --cpus "${cpus}" --memory "${memory}" --disk "${disk}"
fi

# multipass launch/start 在实例进入 Running 时即返回，但它自己与 VM 之间的 SSH 通道
# 还要几秒才可达；紧接着执行 transfer/exec 会得到
# `ssh connection failed: 'Failed to connect: No route to host'`。
# 因此必须显式等待就绪，而不是假定 launch 返回就等于可用。
wait_ready() {
  local attempts=60
  local index
  for ((index = 1; index <= attempts; index++)); do
    if multipass exec "${vm_name}" -- true >/dev/null 2>&1; then
      ((index > 1)) && echo "VM 在第 ${index} 次探测时就绪。"
      return 0
    fi
    sleep 2
  done
  fail "VM ${vm_name} 在 $((attempts * 2)) 秒内未就绪；请检查 multipass list 与 multipass info ${vm_name}"
}

echo "等待 VM 就绪..."
wait_ready

# 两种独立解析并校验，避免依赖某一版 multipass 的输出列序。
vm_ip="$(multipass info "${vm_name}" --format csv 2>/dev/null | awk -F, 'NR==2 {print $3}')"
if [[ ! ${vm_ip} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  vm_ip="$(multipass info "${vm_name}" | awk '/^IPv4/ {print $2; exit}')"
fi
[[ ${vm_ip} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "无法获取 VM IPv4 地址（解析结果: ${vm_ip:-空}）"
echo "VM 地址: ${vm_ip}"

# 公钥不是机密，但仍用 transfer 而非内联 heredoc：避免依赖 multipass exec 的 stdin 转发。
multipass transfer "${key_path}.pub" "${vm_name}:/tmp/huntwarden-operator.pub"
multipass exec "${vm_name}" -- bash -c '
set -euo pipefail
mkdir -p "${HOME}/.ssh"
chmod 700 "${HOME}/.ssh"
touch "${HOME}/.ssh/authorized_keys"
key="$(cat /tmp/huntwarden-operator.pub)"
grep -qxF "${key}" "${HOME}/.ssh/authorized_keys" || printf "%s\n" "${key}" >> "${HOME}/.ssh/authorized_keys"
chmod 600 "${HOME}/.ssh/authorized_keys"
rm -f /tmp/huntwarden-operator.pub
'
echo "已注入验收公钥。"

# 带外读取：走 multipass 的 hypervisor 通道，不经 SSH，因此可以作为可信来源。
host_key_line="$(multipass exec "${vm_name}" -- cat /etc/ssh/ssh_host_ed25519_key.pub)"
[[ -n ${host_key_line} ]] || fail "无法读取目标 Host Key"
fingerprint="$(printf '%s\n' "${host_key_line}" | ssh-keygen -lf - -E sha256 | awk '{print $2}')"
[[ ${fingerprint} =~ ^SHA256:[A-Za-z0-9+/]+$ ]] || fail "Host Key 指纹格式异常: ${fingerprint}"

known_hosts="${state_dir}/known_hosts"
key_type="$(printf '%s\n' "${host_key_line}" | awk '{print $1}')"
key_body="$(printf '%s\n' "${host_key_line}" | awk '{print $2}')"
tmp_known="$(mktemp)"
trap 'rm -f "${tmp_known}"' EXIT
if [[ -f ${known_hosts} ]]; then
  grep -v "^${vm_ip} " "${known_hosts}" > "${tmp_known}" || :
fi
printf '%s %s %s\n' "${vm_ip}" "${key_type}" "${key_body}" >> "${tmp_known}"
mv -f "${tmp_known}" "${known_hosts}"
trap - EXIT
chmod 600 "${known_hosts}"

echo "Host Key 指纹（带外读取，请与 VM 控制台再核对一次）:"
echo "  ${fingerprint}"
echo "known_hosts: ${known_hosts}"

# ---------- 阶段 2：传输仓库并安装 Helper ----------

step "阶段 2：传输仓库并安装 Helper"

# install-helper.sh 从仓库根解析规则与探针路径，因此必须带上整个仓库而非只有 host-helper/。
# 先打包再 multipass transfer：node_modules 与构建产物不需要，且 transfer 传单文件
# 比递归拷贝数万个小文件快得多，也不依赖 multipass exec 的 stdin 转发行为。
echo "传输仓库到 ${vm_name}:${REMOTE_REPO} ..."
repo_tar="$(mktemp -t huntwarden-repo)"
trap 'rm -f "${repo_tar}"' EXIT
# COPYFILE_DISABLE=1 与 --no-xattrs/--no-mac-metadata 阻止 bsdtar 写入 macOS 扩展属性；
# 否则 GNU tar 解包时会为几乎每个文件打印一行
# `Ignoring unknown extended header keyword 'LIBARCHIVE.xattr.com.apple.*'`，
# 数百行噪声会把安装与自检的真实输出淹掉。
COPYFILE_DISABLE=1 tar -C "${repo_root}" \
  --no-xattrs --no-mac-metadata --no-fflags \
  --exclude='./node_modules' --exclude='./.git' --exclude='./out' --exclude='./dist' \
  --exclude='./release' --exclude='./data' --exclude='./labs/.lab-state' \
  -cf "${repo_tar}" .
multipass exec "${vm_name}" -- bash -c "rm -rf '${REMOTE_REPO}' && mkdir -p '${REMOTE_REPO}'"
multipass transfer "${repo_tar}" "${vm_name}:/tmp/huntwarden-repo.tar"
multipass exec "${vm_name}" -- tar -C "${REMOTE_REPO}" -xf /tmp/huntwarden-repo.tar
multipass exec "${vm_name}" -- rm -f /tmp/huntwarden-repo.tar
rm -f "${repo_tar}"
trap - EXIT
echo "传输完成。"

run_install() {
  local label="$1"
  local code=0
  step "阶段 2：${label}"
  # 状态必须单独捕获：`if cmd; then …; fi` 在条件失败且无 else 时整体退出码为 0，
  # 在 fi 之后读 $? 会把真实错误码读成 0。
  multipass exec "${vm_name}" -- sudo "${REMOTE_REPO}/host-helper/install-helper.sh" \
    --executor-user "${VM_USER}" --self-check || code=$?
  if ((code == 0)); then
    echo "${label}：自检退出码 0（可能含非核心降级，见上方摘要）。"
    return 0
  fi
  case "${code}" in
    1) >&2 echo "${label}：自检报告核心能力缺失或组件问题（退出码 1）。" ;;
    3) >&2 echo "${label}：Helper 协议版本与控制端要求不一致（退出码 3）。" ;;
    *) >&2 echo "${label}：安装或自检失败（退出码 ${code}）。" ;;
  esac
  return "${code}"
}

install_status=0
run_install "最低依赖安装与自检" || install_status=$?
if ((install_status != 0)); then
  >&2 echo "最低依赖阶段未通过。这一遍的目的是记录降级行为，"
  >&2 echo "若失败原因是核心能力（root Helper/sudo/proc 可见性）而非可选依赖，请先修复再继续。"
  exit "${install_status}"
fi

if ((full_deps == 1)); then
  step "阶段 2：安装完整依赖"
  echo "安装: ${FULL_DEPS[*]}"
  multipass exec "${vm_name}" -- sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  multipass exec "${vm_name}" -- sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${FULL_DEPS[@]}"
  run_install "完整依赖复检"
else
  echo
  echo "未加 --full-deps，只完成了最低依赖那一遍。"
  echo "Gate B 要求两遍：补齐依赖后请重跑本脚本并加 --full-deps。"
fi

# ---------- 阶段 3：生成验收环境变量 ----------

step "阶段 3：生成验收环境变量"

release_info="$(multipass exec "${vm_name}" -- bash -c '. /etc/os-release && printf "%s %s" "${ID}" "${VERSION_ID}"')"
distro="$(printf '%s' "${release_info}" | awk '{print $1}')"
version="$(printf '%s' "${release_info}" | awk '{print $2}')"
arch="$(multipass exec "${vm_name}" -- uname -m)"
kernel="$(multipass exec "${vm_name}" -- uname -r)"

env_file="${state_dir}/${vm_name}.env"
umask 077
cat > "${env_file}" <<ENVFILE
# HuntWarden 真实 VM 验收环境变量。含真实地址与 Host Key 指纹，禁止提交到仓库。
# 用法: source ${env_file} && npm run test:acceptance:vm
export HUNTWARDEN_VM_CONFIRM_READ_ONLY=I_HAVE_AUTHORIZATION
export HUNTWARDEN_VM_HOST=${vm_ip}
export HUNTWARDEN_VM_PORT=22
export HUNTWARDEN_VM_USER=${VM_USER}
export HUNTWARDEN_VM_FINGERPRINT='${fingerprint}'
export HUNTWARDEN_VM_PRIVATE_KEY=${key_path}
export HUNTWARDEN_VM_KNOWN_HOSTS=${known_hosts}
export HUNTWARDEN_VM_EXPECT_DISTRO=${distro}
export HUNTWARDEN_VM_EXPECT_VERSION=${version}
export HUNTWARDEN_VM_EXPECT_ARCH=${arch}
ENVFILE
chmod 600 "${env_file}"

# 直接输出「字段: 值」而不做列对齐：printf 的 %-Ns 按字节补齐，中日韩字符是双宽，
# 对齐结果反而更乱。这段内容是给人抄进验收模板的，可读性优先。
step "目标身份（填入 VM_ACCEPTANCE_TEMPLATE.md 第 2 节）"
echo "镜像来源: Multipass 官方镜像 ${image}"
echo "发行版: ${distro} ${version}"
echo "架构: ${arch}"
echo "内核: ${kernel}"
echo "Host Key 指纹: ${fingerprint}"
echo "带外核验: 经 multipass exec 读取，未使用 ssh-keyscan"

step "下一步"
cat <<NEXT
1. 只读冒烟（4 例，零写操作）：
     source ${env_file}
     npm run test:acceptance:vm

2. GUI 完整验收（五类 × QUICK/STANDARD/DEEP、无害夹具、报告引用校验）：
     multipass exec ${vm_name} -- sudo ${REMOTE_REPO}/acceptance/vm/install-safe-fixtures.sh --install
     npm run start:gui
   验收要点与清理步骤见 acceptance/vm/README.md。

3. 回填：
     cp docs/acceptance/VM_ACCEPTANCE_TEMPLATE.md \\
        docs/acceptance/VM_${distro}_${version}_${arch}_\$(date +%F).md

4. 销毁：
     acceptance/vm/bootstrap-multipass.sh --name ${vm_name} --destroy
NEXT

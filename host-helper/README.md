# HuntWarden 目标端 Helper

Helper 是 root 所有的固定操作入口，只接受白名单操作名和 stdin JSON，不接受 Shell 字符串。

## Debian / Ubuntu

```bash
sudo apt-get install -y python3 sudo
sudo ./host-helper/install-helper.sh --executor-user <SSH用户> --probe-source ./java/build/libs/huntwarden-tomcat-probe.jar --self-check
```

## Rocky / AlmaLinux / Amazon Linux

```bash
sudo dnf install -y python3 sudo
sudo ./host-helper/install-helper.sh --executor-user <SSH用户> --probe-source ./java/build/libs/huntwarden-tomcat-probe.jar --self-check
```

再次运行安装脚本会原子更新 Helper、Probe 与 sudoers 配置，可用于升级。卸载默认保留动作回执、隔离内容和 Artifact 状态：

```bash
sudo ./host-helper/uninstall-helper.sh
```

仅在明确不再需要恢复或取证数据时使用：

```bash
sudo ./host-helper/uninstall-helper.sh --purge-state
```

独立自检：

```bash
sudo ./host-helper/self-check-helper.sh --executor-user <SSH用户>
```

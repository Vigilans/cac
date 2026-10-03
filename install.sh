#!/usr/bin/env bash
# install.sh — cac 一键安装脚本
set -euo pipefail

REPO="https://raw.githubusercontent.com/nmhjklnm/cac/master"
CAC_DIR="${CAC_DIR:-$HOME/.cac}"
BIN_DIR="$HOME/.local/bin"

# 颜色
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red() { printf '\033[31m%s\033[0m\n' "$*"; }

echo "=== cac — Claude Code Cloak 安装 ==="
echo

# 1. 检查是否已通过 npm 安装
if command -v cac &>/dev/null; then
    local_cac=$(command -v cac)
    if [[ -L "$local_cac" ]]; then
        cac_link=$(readlink "$local_cac")
        if [[ "$cac_link" = /* ]]; then local_cac="$cac_link"
        else local_cac="$(dirname "$local_cac")/$cac_link"; fi
    fi
    if [[ "$local_cac" == *"node_modules"* ]] || [[ -f "$(dirname "$local_cac" 2>/dev/null)/package.json" ]]; then
        red "⚠ 检测到已通过 npm 安装 claude-cac，请勿同时使用两种安装方式！"
        echo "  如需切换到 bash 安装，请先执行："
        echo "    npm uninstall -g claude-cac"
        exit 1
    fi
fi

# 2. 下载完整 runtime，再发布到选定目录
mkdir -p "$CAC_DIR" "$BIN_DIR"
CAC_DIR=$(cd "$CAC_DIR" && pwd -P)
stage=$(mktemp -d "$CAC_DIR/.install.XXXXXX")
trap 'rm -rf "$stage"' EXIT
printf "下载 cac ... "
curl -fsSL "$REPO/cac" -o "$stage/cac"
for asset in fingerprint-hook.js relay.js; do
    curl -fsSL "$REPO/src/$asset" -o "$stage/$asset"
done
bash -n "$stage/cac"
chmod +x "$stage/cac"
for asset in cac fingerprint-hook.js relay.js; do
    mv -f "$stage/$asset" "$CAC_DIR/$asset"
done
green "✓"

# 3. 初始化并生成固定目录入口
export PATH="$BIN_DIR:$PATH"
CAC_DIR="$CAC_DIR" "$CAC_DIR/cac" env ls >/dev/null
{
    printf '#!/bin/bash\n# cac launcher\n'
    printf 'export CAC_DIR=%q\n' "$CAC_DIR"
    printf 'exec "$CAC_DIR/cac" "$@"\n'
} > "$stage/launcher"
chmod +x "$stage/launcher"
mv -f "$stage/launcher" "$BIN_DIR/cac"

echo
green "✓ 安装完成：$BIN_DIR/cac ($CAC_DIR)"
echo

# 4. 提示生效方式
RC_FILE=""
if [[ "$(basename "${SHELL:-}")" == "fish" ]]; then
    RC_FILE="$HOME/.config/fish/config.fish"
elif [[ -f "$HOME/.zshrc" ]]; then
    RC_FILE="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
    RC_FILE="$HOME/.bashrc"
elif [[ -f "$HOME/.bash_profile" ]]; then
    RC_FILE="$HOME/.bash_profile"
fi

if [[ -n "$RC_FILE" ]] && grep -q '# >>> cac' "$RC_FILE"; then
    echo "执行以下命令使配置生效（或重开终端）："
    echo "  source $RC_FILE"
    echo
fi
echo "然后添加第一个代理配置："
echo "  cac env create <名字> -p <host:port:user:pass>"

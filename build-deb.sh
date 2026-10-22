#!/bin/bash
# build-deb.sh — 把 Synapse 打成标准 .deb
#   源件: synapse*.py(主程序+判定层+探测层), man/synapse.1, debian-doc/*, packaging-src/*
#   生成: packaging/usr/**, dist/*.deb
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(awk '/^Version:/{print $2}' packaging-src/DEBIAN/control)
OUT="dist"
PKG="synapse_${VERSION}_all.deb"
U="packaging/usr"

# 0) 清掉上轮生成物, 避免残留(尤其数据文件)
rm -rf "$U" packaging/DEBIAN
mkdir -p "$U" packaging/DEBIAN

# 0.5) 控制文件也是源件, 从 packaging-src 复制(避免源码/生成物混在一棵树里)
install -m644 packaging-src/DEBIAN/control packaging/DEBIAN/control
install -m755 packaging-src/DEBIAN/postinst packaging/DEBIAN/postinst

# 1) 程序 -> /usr/lib/synapse
#    synapse.py 入口(CLI/状态/台账), synapse_classify.py 判定层,
#    synapse_probe.py 探测层, synapse_dashboard.py 渲染层(纯函数, 数据→HTML)。
#    四个模块平铺在同一目录, 因为运行时靠 sys.path[0](脚本所在目录)互相 import。
for f in synapse.py synapse_classify.py synapse_probe.py synapse_dashboard.py; do
    install -Dm644 "$f" "$U/lib/synapse/$f"
done

# 2) 入口壳 -> /usr/bin
install -Dm755 packaging-src/bin-synapse "$U/bin/synapse" 2>/dev/null || true

# 3) man 手册: 源在 man/synapse.1, 打包只收 .gz
gzip -9 -n -c man/synapse.1 > /tmp/synapse.1.gz
install -Dm644 /tmp/synapse.1.gz "$U/share/man/man1/synapse.1.gz"

# 4) Debian 文档: changelog.Debian.gz + copyright(lintian 必查)
install -Dm644 debian-doc/copyright "$U/share/doc/synapse/copyright"
gzip -9 -n -c debian-doc/changelog.Debian > /tmp/changelog.Debian.gz
install -Dm644 /tmp/changelog.Debian.gz "$U/share/doc/synapse/changelog.Debian.gz"
install -Dm644 packaging-src/doc/README "$U/share/doc/synapse/README"

# 5) systemd 用户单元
for f in packaging-src/systemd/*; do
    install -Dm644 "$f" "$U/lib/systemd/user/$(basename "$f")"
done

# 6) bash 补全
install -Dm644 packaging-src/bash-completion/synapse \
    "$U/share/bash-completion/completions/synapse"

# 7) 桌面入口 + 图标: 没有 .desktop 时, 装完在 KRunner/GNOME 启动器里
#    搜不到任何东西, 用户会以为"没装上"。
install -Dm644 packaging-src/desktop/synapse.desktop \
    "$U/share/applications/synapse.desktop"
install -Dm644 packaging-src/desktop/synapse.svg \
    "$U/share/icons/hicolor/scalable/apps/synapse.svg"

# 8) 构建前清点: 包里绝不能有数据/密钥文件
for f in config.json STATIONS.md issues.json .outage.json \
         .targets_snapshot.json .dirty reports; do
    if [ -e "packaging/usr/lib/synapse/$f" ] || [ -e "packaging/$f" ]; then
        echo "[!] 打包中止: 包骨架里混入了数据文件 $f" >&2
        exit 1
    fi
done
if grep -rIl 'sk-[A-Za-z0-9]\{16,\}' packaging/ 2>/dev/null | grep -q .; then
    echo "[!] 打包中止: 包内容里出现疑似 API key" >&2
    grep -rIl 'sk-[A-Za-z0-9]\{16,\}' packaging/ 2>/dev/null >&2
    exit 1
fi

# 9) dpkg-deb 出包(rootless: 强制 root:root)
mkdir -p "$OUT"; rm -f "$OUT/$PKG"
dpkg-deb --root-owner-group --build packaging "$OUT/$PKG"

echo
echo "== 包内容 =="
dpkg-deb -c "$OUT/$PKG"
if command -v lintian >/dev/null 2>&1; then
    echo; echo "== lintian =="; lintian "$OUT/$PKG" || true
else
    echo; echo "[i] 未装 lintian(apt install lintian 可做合规检查)"
fi
echo; echo "[OK] $OUT/$PKG"

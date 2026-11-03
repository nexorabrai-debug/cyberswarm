#!/usr/bin/env bash
# Baixa os laboratórios/ferramentas EXTERNOS (não vão no zip). Tudo gratuito/OSS, de fontes oficiais.
set -euo pipefail
L=${CYBERSWARM_LABS:-$HOME/labs}; T=$HOME/.cyberswarm-tools; mkdir -p "$L" "$T/bin" "$T/ext"; cd "$L"
gh(){ curl -fsSL -o "$2" "https://github.com/$1"; }
[ -f nuclei.zip ] || gh projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip nuclei.zip
unzip -oq nuclei.zip nuclei -d "$T/bin"
[ -d nuclei-templates ] || "$T/bin/nuclei" -update-templates -ud "$L/nuclei-templates" -silent
[ -f js.tgz ] || gh juice-shop/juice-shop/releases/download/v20.3.0/juice-shop-20.3.0_node22_linux_x64.tgz js.tgz
[ -d juice-shop ] || { tar xzf js.tgz; mv juice-shop_20.3.0 juice-shop; }
if [ ! -d node22 ]; then V=$(curl -s https://nodejs.org/dist/latest-v22.x/ | grep -o 'v22\.[0-9.]*-linux-x64.tar.xz' | head -1); curl -fsSL -o node22.tar.xz "https://nodejs.org/dist/latest-v22.x/node-$V"; tar xf node22.tar.xz; mv node-v22*-linux-x64 node22; fi
[ -f webgoat.jar ] || gh WebGoat/WebGoat/releases/download/v2026.4/webgoat-2026.4.jar webgoat.jar
if [ ! -d jre ]; then curl -fsSL -o jre.tgz "https://api.adoptium.net/v3/binary/latest/25/ga/linux/x64/jre/hotspot/normal/eclipse"; mkdir jre; tar xzf jre.tgz -C jre --strip-components=1; fi
[ -d VAmPI ] || git clone -q https://github.com/erev0s/VAmPI && git -C VAmPI checkout -q f16052d
[ -d dvga ] || git clone -q https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application dvga && git -C dvga checkout -q a961308
[ -d crapi ] || git clone -q --depth 50 https://github.com/OWASP/crAPI crapi
[ -d ibsrc ] || git clone -q https://github.com/dineshshetty/Android-InsecureBankv2 ibsrc && git -C ibsrc checkout -q 3c8cc3a
cp -n ibsrc/InsecureBankv2.apk . 2>/dev/null || true
# Python labs em venvs isolados (requisitos antigos exigem Python 3.10/3.11 -> uv)
[ -d VAmPI/.v ] || (cd VAmPI && uv venv -q -p 3.11 .v && VIRTUAL_ENV=.v uv pip install -q -r requirements.txt)
[ -d dvga/.v ] || (cd dvga && uv venv -q -p 3.10 .v && VIRTUAL_ENV=.v uv pip install -q -r requirements.txt)
# Ferramentas Python no venv de ferramentas
[ -x "$T/bin/python" ] || python3 -m venv "$T"
"$T/bin/pip" install -q androguard bandit semgrep sslyze checkov
# MobSF (opcional, pesado) em venv próprio Python 3.12
[ -d mobsf-v ] || { uv venv -q -p 3.12 mobsf-v && VIRTUAL_ENV=mobsf-v uv pip install -q mobsf; }
# nmap: apt bloqueado nesta máquina -> extrai .deb oficiais do Debian sem instalar (dpkg -x)
if ! command -v nmap >/dev/null && [ ! -x "$T/bin/nmap" ]; then
  P=http://deb.debian.org/debian/pool/main
  for u in n/nmap/nmap_7.95+dfsg-3_amd64.deb n/nmap/nmap-common_7.95+dfsg-3_all.deb libp/libpcap/libpcap0.8t64_1.10.5-2_amd64.deb libl/liblinear/liblinear4_2.3.0+dfsg-5+b3_amd64.deb l/lua5.4/liblua5.4-0_5.4.9-2_amd64.deb; do
    curl -fsSLO "$P/$u"; dpkg -x "$(basename "$u")" "$T/ext/nmap"; done
  printf '#!/bin/sh\nT=%s\nLD_LIBRARY_PATH=$T/usr/lib/x86_64-linux-gnu exec $T/usr/bin/nmap --datadir $T/usr/share/nmap "$@"\n' "$T/ext/nmap" > "$T/bin/nmap"; chmod +x "$T/bin/nmap"
fi
# --- Etapa C (2.0): ferramentas SCA/segredos, binários oficiais com SHA256 do checksums.txt da release ---
fetch_tool() {  # url sha256 nome-no-arquivo
  f="$T/ext/$(basename "$1")"; [ -f "$f" ] || curl -fsSL -o "$f" "$1"
  echo "$2  $f" | sha256sum -c - || { echo "checksum falhou: $1"; rm -f "$f"; return 1; }
  case "$f" in *.tar.gz) tar -xzf "$f" -C "$T/bin" "$3";; *) cp "$f" "$T/bin/$3"; chmod +x "$T/bin/$3";; esac; }
fetch_tool https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb gitleaks
fetch_tool https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b osv-scanner
fetch_tool https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 trivy
fetch_tool https://github.com/anchore/grype/releases/download/v0.121.1/grype_0.121.1_linux_amd64.tar.gz bc3ea3f9e6fd56ac781c08c6c5e614271b79f438200757f6932085c19b0a4657 grype
fetch_tool https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_linux_amd64.tar.gz 1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528 syft
"$T/bin/python3" -m pip install -q yara-python==4.5.4 2>/dev/null || true
echo "ok: labs em $L"

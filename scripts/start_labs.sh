#!/usr/bin/env bash
# Sobe os laboratórios SOMENTE em 127.0.0.1. Uso: scripts/start_labs.sh [juice-shop|webgoat|vampi|dvga|mobsf|all]
L=${CYBERSWARM_LABS:-$HOME/labs}; cd "$L"; W=${1:-all}; R=$(cd "$(dirname "$0")" && pwd)
up(){ [ "$W" = all ] || [ "$W" = "$1" ]; }
up juice-shop && (cd juice-shop && PORT=3000 nohup ../node22/bin/node -r "$R/bind-local.js" build/app.js > ../juice.log 2>&1 &)
up webgoat && (WEBGOAT_PORT=8080 WEBWOLF_PORT=9090 WEBGOAT_HOST=127.0.0.1 WEBWOLF_HOST=127.0.0.1 nohup jre/bin/java -Xmx1g -Dserver.address=127.0.0.1 -jar webgoat.jar > wg.log 2>&1 &)
if up vampi; then (cd VAmPI && sed "s/host='0.0.0.0', port=5000, debug=True/host='127.0.0.1', port=5002, debug=False/" app.py > run_local.py && vulnerable=1 nohup .v/bin/python run_local.py > ../vampi.log 2>&1 &); sleep 3; curl -s -o /dev/null http://127.0.0.1:5002/createdb; fi
up dvga && (cd dvga && .v/bin/python setup.py >/dev/null 2>&1; PATH=$PWD/.v/bin:$PATH nohup .v/bin/python app.py > ../dvga.log 2>&1 &)
if up mobsf; then [ -f mobsf.key ] || { echo "lab-local-$(openssl rand -hex 8)" > mobsf.key; chmod 600 mobsf.key; }
  (JAVA_HOME=$L/jre PATH=$L/jre/bin:$PATH MOBSF_API_KEY=$(cat mobsf.key) nohup mobsf-v/bin/mobsf 127.0.0.1:8000 > mobsf.log 2>&1 &); fi
echo "iniciado: $W (verifique: cyberswarm hacker labs)"

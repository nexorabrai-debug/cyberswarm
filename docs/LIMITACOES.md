# Limitações conhecidas — CyberSwarm 2.0

1. **Cobertura de labs longe de 100%** (Juice Shop ~2,6%, WebGoat 0%, VAmPI 44%, DVGA 13%, APK 52%).
2. **WebGoat**: sem crawler autenticado por lição; Java/apt bloqueados neste box para tooling extra.
3. **crAPI**: exige Docker — indisponível aqui.
4. **ZAP / Ghidra / JADX / Garak / DefectDojo / Prowler**: não integrados (Java/Docker/credenciais).
5. **OSV-Scanner** fala com api.osv.dev (online). Desative com `CYBERSWARM_DISABLE_TOOLS=osv-scanner`.
6. **Checkpoint** é por tarefa de agente; Nuclei longo recomeça se morto no meio.
7. **PWA** exige HTTPS ou localhost para instalar.
8. **Certificado autoassinado**: o celular mostra aviso (esperado).
9. **ThreadingHTTPServer**: ok para uso pessoal; não é CDN/WAF.
10. **Sem 2FA** / recuperação de senha.
11. **POST ativo** só em 127.0.0.1 — clientes reais continuam só com métodos passivos + aprovação para testes ativos do núcleo.
12. **Confiança/contradição** são heurísticas, não calibradas.
13. **APK nativo**: não compilado neste box — `which java javac sdkmanager` vazios em 2026-11-03; use PWA (Chrome → Adicionar à tela inicial). Bubblewrap documentado em MANUAL_A32.md [não testado].
14. **Oracle/GCP/Cloudflare conta**: documentados, [não testados] aqui.

"use strict";
// CyberSwarm Control — SPA sem segredos: a sessão é um cookie HttpOnly; o token CSRF vem de /api/me e fica só em memória.
let ME = null, timer = null;
const $ = s => document.querySelector(s), app = $("#app");
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const pill = v => `<span class="pill ${esc(v)}">${esc(v)}</span>`;
const dt = t => t ? new Date(t * 1000).toLocaleString("pt-BR", {timeZone: "America/Sao_Paulo"}) : "—";
const brl = c => (c / 100).toLocaleString("pt-BR", {style: "currency", currency: "BRL"});

/* reconexão / offline */
(function netBanner(){
  const b = document.createElement("div"); b.id = "net-banner"; b.hidden = true;
  b.style.cssText = "position:sticky;top:0;z-index:99;background:#b45309;color:#fff;padding:8px 12px;font-size:13px;text-align:center";
  b.innerHTML = 'Sem rede — shell offline. <button id="net-retry" style="margin-left:8px">Tentar de novo</button>';
  document.documentElement.prepend(b);
  const show = on => { b.hidden = !on; };
  window.addEventListener("offline", () => show(true));
  window.addEventListener("online", () => { show(false); try { route(); } catch(e) {} });
  document.addEventListener("click", e => { if (e.target && e.target.id === "net-retry") { show(!navigator.onLine); try { route(); } catch(err) {} } });
  if (!navigator.onLine) show(true);
})();

async function api(path, opt = {}) {
  const h = {"Accept": "application/json"};
  if (opt.body !== undefined) h["Content-Type"] = "application/json";
  if (opt.method && opt.method !== "GET" && ME) h["X-CSRF-Token"] = ME.csrf;
  const r = await fetch(path, {method: opt.method || "GET", headers: h, body: opt.body !== undefined ? JSON.stringify(opt.body) : undefined, credentials: "same-origin"});
  const d = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "/api/login") { ME = null; location.hash = "#/login"; throw new Error("sessão expirada"); }
  if (!r.ok) throw new Error(d.erro || ("HTTP " + r.status));
  return d;
}
const PAGES = [["dashboard","Painel"],["chat","Chat"],["hacker","Hacker AI"],["jobs","Tarefas"],["approvals","Aprovações"],["clients","Escopos"],["findings","Achados"],
  ["compare","Comparar"],["reports","PDFs"],["tools","Módulos"],["settings","Ajustes"],["logs","Logs"],["finance","Financeiro"]];
function navbar(cur) {
  const n = $("#nav"); n.hidden = !ME; $("#menu").hidden = !ME;
  n.innerHTML = PAGES.map(([k, t]) => `<a href="#/${k}" class="${k === cur ? "on" : ""}">${t}</a>`).join("") + (ME ? `<a href="#/logout">Sair</a>` : "");
  $("#who").textContent = ME ? `${ME.username} · ${ME.role === "owner" ? "proprietário" : "leitura"} · somente escopo autorizado` : "defensivo · 127.0.0.1";
}
$("#menu").onclick = () => $("#nav").classList.toggle("open");
const owner = () => ME && ME.role === "owner";
function form(el, fn) { el.onsubmit = async e => { e.preventDefault(); const out = el.querySelector(".err"); out && (out.textContent = "");
  try { await fn(Object.fromEntries(new FormData(el))); } catch (x) { out ? out.textContent = x.message : alert(x.message); } }; }
// ---------- páginas ----------
const V = {};
V.login = async () => {
  app.innerHTML = `<div class="card" style="max-width:420px;margin:30px auto"><h2>Entrar</h2><form id="f">
  <label>Usuário</label><input name="username" autocomplete="username" required>
  <label>Senha</label><input name="password" type="password" autocomplete="current-password" required>
  <button>Entrar</button><p class="err"></p></form><p class="mut">5 tentativas erradas bloqueiam por 15 min. Nenhuma senha é guardada no app.</p></div>`;
  form($("#f"), async d => { ME = await api("/api/login", {method: "POST", body: d}); location.hash = "#/dashboard"; });
};

V.chat = async () => {
  const threads = await api("/api/chat/threads"), cl = await api("/api/clients");
  let tid = location.hash.split("/")[2];
  if (!tid && threads[0]) tid = String(threads[0].id);
  const head = `<h2>Chat de comandos</h2>
    <div class="row" style="margin-bottom:8px">${owner() ? `<select id="ncid"><option value="_lab">Laboratório</option>${cl.map(c => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join("")}</select>
    <button id="nchat" class="sec">Nova conversa</button>` : ""}</div>
    <div class="row" style="margin-bottom:8px;overflow-x:auto">${threads.map(t => `<a class="btn ${String(t.id)===String(tid)?"":"sec"}" href="#/chat/${t.id}">#${t.id} ${esc(t.title||t.client_id)}</a>`).join("") || "<span class=mut>nenhuma conversa</span>"}</div>`;
  if (!tid) { app.innerHTML = head + `<p class="card mut">Crie uma conversa para falar com o Hacker AI. Sem IA configurada, o parser de regras planeja na mesma.</p>`;
    if (owner()) $("#nchat").onclick = async () => { const r = await api("/api/chat/threads", {method:"POST", body:{client_id:$("#ncid").value, title:"Conversa"}}); location.hash = "#/chat/"+r.id; };
    return; }
  const d = await api("/api/chat/threads/" + tid);
  app.innerHTML = head + `<div class="card"><div class="mut">cliente ${esc(d.thread.client_id)} · #${tid}</div>
    <div class="chat-box" id="cbox">${d.messages.map(m => `<div class="${m.role==="user"?"chat-me":"chat-bot"}">${esc(m.content)}</div>`).join("") || "<span class=mut>assistente de comandos (não é LLM). Ex.: verificar cabeçalhos do laboratório — confirmo com «escopo autorizado»</span>"}</div>
    ${owner() ? `<div class="chat-input"><textarea id="cmsg" rows="2" placeholder="Ordem clara (ex.: verificar cabeçalhos do lab) · status · ajuda"></textarea><button id="csend">Enviar</button></div>` : ""}</div>`;
  const box = $("#cbox"); box.scrollTop = box.scrollHeight;
  if (owner()) {
    $("#nchat").onclick = async () => { const r = await api("/api/chat/threads", {method:"POST", body:{client_id:$("#ncid").value}}); location.hash = "#/chat/"+r.id; };
    const send = async () => {
      const t = $("#cmsg").value.trim(); if (!t) return; $("#cmsg").value = ""; $("#csend").disabled = true;
      try { await api("/api/chat/threads/"+tid+"/messages", {method:"POST", body:{content:t}}); route(); }
      catch (e) { alert(e.message); $("#csend").disabled = false; }
    };
    $("#csend").onclick = send; $("#cmsg").onkeydown = e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } };
  }
};
V.settings = async () => {
  const s = await api("/api/settings");
  app.innerHTML = `<h2>Ajustes de modelos e agentes</h2>
    <div class="card"><p>Provedor ativo: <b>${esc(s.provider_ativo)}</b> ${s.provider_disponivel ? pill("disponível") : pill("indisponível")} · modo determinístico: ${s.deterministic ? pill("ligado") : pill("desligado")}</p>
    <p class="mut">Chaves nunca voltam ao app. Sem provedor, o parser de regras (sempre ligado) planeja as missões.</p></div>
    ${owner() ? `<form id="f" class="card"><h3>Provedor de IA</h3>
      <label>Modo</label><select name="mode"><option value="none" ${s.mode==="none"?"selected":""}>none (só regras)</option>
        <option value="ollama" ${s.mode==="ollama"?"selected":""}>ollama (local)</option>
        <option value="openai" ${s.mode==="openai"?"selected":""}>OpenAI-compatível (HTTPS)</option></select>
      <label>Base URL (ollama: http://127.0.0.1:11434 · openai: https://…/v1)</label><input name="base_url" value="${esc(s.base_url||"")}">
      <label>Modelo</label><input name="model" value="${esc(s.model||"")}">
      <label>API key ${s.has_api_key ? "(já configurada — deixe em branco para manter)" : ""}</label><input name="api_key" type="password" autocomplete="new-password" placeholder="não é exibida depois">
      <label><input type="checkbox" name="clear_api_key" value="1" style="width:auto"> apagar chave</label>
      <label><input type="checkbox" name="deterministic" value="1" style="width:auto" ${s.deterministic?"checked":""}> modo determinístico (sem IA; operações complexas exigem plano pré-aprovado)</label>
      <button>Salvar</button><p class="err"></p></form>` : `<p class="card mut">Somente owner altera.</p>`}`;
  if (!owner()) return;
  form($("#f"), async d => {
    d.deterministic = !!d.deterministic; d.clear_api_key = !!d.clear_api_key;
    if (!d.api_key) delete d.api_key;
    await api("/api/settings", {method:"POST", body:d}); route();
  });
};

V.logout = async () => { try { await api("/api/logout", {method: "POST"}); } catch (e) {} ME = null; location.hash = "#/login"; };
V.dashboard = async () => {
  const d = await api("/api/dashboard"), m = await api("/api/monitor");
  const s = d.achados_por_severidade, st = d.jobs_por_status;
  app.innerHTML = `<h2>Painel geral</h2><div class="grid">
   ${[["Tarefas em execução", st.executando || 0], ["Na fila", st.na_fila || 0], ["Aprovações pendentes", d.aprovacoes_pendentes], ["Clientes", d.clientes],
      ["Achados confirmados", d.confirmados], ["Concluídas", st.concluida || 0]].map(([k, v]) => `<div class="card kpi"><b>${esc(v)}</b><span>${k}</span></div>`).join("")}</div>
   <div class="card"><h3>Achados por severidade (últimas 50 tarefas)</h3><div class="row">${Object.keys(s).sort().map(k => `${pill(k)} ${esc(s[k])}`).join(" &nbsp; ") || "<span class=mut>nenhum ainda</span>"}</div></div>
   <div class="card"><h3>Sistema</h3><span class="mut">workers ${m.workers_vivos}/${m.workers_total} · fila ${m.fila} · disco livre ${m.disco_livre_gb} GB · trilha de auditoria ${m.auditoria_integra ? "íntegra ✔" : "ALTERADA ✖ linha " + m.auditoria_linha_quebrada}</span></div>
   <div class="card"><h3>Últimas tarefas</h3>${jobsTable(d.ultimas)}</div>`;
  timer = setTimeout(route, 5000);
};
const jobsTable = js => js.length ? `<div class="table-wrap"><table><tr><th>#</th><th>Cliente</th><th>Objetivo</th><th>Estado</th><th>Achados</th></tr>${js.map(j =>
  `<tr><td><a href="#/job/${j.id}">${j.id}</a></td><td>${esc(j.client_id === "_lab" ? "laboratório" : j.client_id)}</td><td>${esc(j.kind === "extval" ? "validação externa" : j.goal)}</td><td>${pill(j.status)}</td><td>${esc(j.findings ?? "—")}</td></tr>`).join("")}</table></div>` : `<p class="mut">Nenhuma tarefa ainda.</p>`;
V.jobs = async () => { const js = await api("/api/jobs"); app.innerHTML = `<h2>Agentes e tarefas</h2><div class="card">${jobsTable(js)}</div>`; timer = setTimeout(route, 5000); };
V.hacker = async () => {
  const cl = await api("/api/clients"), t = await api("/api/tools");
  app.innerHTML = `<h2>Hacker AI — novo objetivo</h2>${owner() ? `<form id="f" class="card">
   <label>Cliente / escopo</label><select name="client_id" id="cid"><option value="_lab">Laboratório interno (127.0.0.1)</option>${cl.map(c => `<option value="${esc(c.id)}" ${c.vigente ? "" : "disabled"}>${esc(c.name)} ${c.vigente ? "" : "(termo fora da validade)"}</option>`).join("")}</select>
   <label>Tipo</label><select name="kind" id="kind"><option value="hacker">Missão Hacker AI (planejar + executar + verificar)</option><option value="extval">Validação externa em laboratório</option></select>
   <div id="labsel" hidden><label>Laboratório</label><select name="lab">${t.laboratorios.filter(l => l.estado !== "nao_executavel").map(l => `<option>${esc(l.nome)}</option>`).join("")}</select></div>
   <div id="tg" hidden><label>Alvo (precisa estar no escopo autorizado)</label><input name="target" placeholder="https://www.exemplo.com.br"></div>
   <label>Objetivo (texto livre)</label><textarea name="goal" rows="3" placeholder="Ex.: verificar cabeçalhos, TLS e exposição de API"></textarea>
   <button>Enviar ao Hacker AI</button><p class="err"></p>
   <p class="mut">Testes ativos fora do laboratório só rodam depois de aprovação explícita. O alvo é conferido contra o escopo e o termo de autorização.</p></form>` : `<p class="card mut">Perfil somente leitura.</p>`}
   <div class="card"><h3>Missões recentes</h3>${jobsTable((await api("/api/jobs")).slice(0, 10))}</div>`;
  if (!owner()) return;
  const upd = () => { const lab = $("#cid").value === "_lab"; $("#tg").hidden = lab; $("#labsel").hidden = !(lab && $("#kind").value === "extval"); };
  $("#cid").onchange = $("#kind").onchange = upd; upd();
  form($("#f"), async d => { const r = await api("/api/jobs", {method: "POST", body: d}); location.hash = "#/job/" + r.id; });
};
V.job = async id => {
  const d = await api("/api/jobs/" + id), j = d.job, s = d.summary || {};
  app.innerHTML = `<h2>Tarefa #${esc(j.id)} ${pill(j.status)}</h2><div class="card"><b>${esc(j.goal)}</b><div class="mut">cliente ${esc(j.client_id)} · criada por ${esc(j.created_by)} em ${dt(j.created)} · fim ${dt(j.finished)}</div>
   ${j.error ? `<p class="err">${esc(j.error)}</p>` : ""}${s.modules ? `<p class="mut">módulos: ${esc(s.modules.join(", "))} · negadas: ${esc((s.denied || []).length)} · achados ${esc(s.findings)} (confirmados ${esc(s.confirmed)}) · ${esc(s.elapsed_s)} s</p>` : ""}
   ${s.metricas ? `<p class="mut">revocação ${(s.metricas.revocacao * 100).toFixed(1)}% · detectados ${s.metricas.detectados}/${s.metricas.itens_oficiais}</p>` : ""}
   <div class="row"><a class="btn sec" href="#/findings/${j.id}">Achados</a>${d.arquivos.filter(f => f.endsWith(".pdf")).map(f => `<a class="btn sec" href="#/pdf/${j.id}/${esc(f)}">PDF</a>`).join("")}
    ${owner() && ["na_fila","executando","aguardando_aprovacao"].includes(j.status) ? `<button class="sec" id="jpause">Pausar</button><button class="bad" id="jcancel">Cancelar</button>` : ""}
    ${owner() && j.status === "pausada" ? `<button class="ok" id="jresume">Retomar</button>` : ""}</div>
    ${j.progress ? `<p class="mut">progresso: ${esc(j.progress)} · tentativas ${esc(j.attempts || 0)}</p>` : ""}</div>
   ${d.aprovacoes.length ? `<div class="card"><h3>Aprovações</h3>${d.aprovacoes.map(a => `<div>${pill(a.status)} ${esc(a.op)} → ${esc(a.target)} <span class="mut">${esc(a.decided_by || "")} ${esc(a.reason || "")}</span></div>`).join("")}</div>` : ""}
   <div class="card"><h3>Agentes</h3>${d.tasks.length ? `<div class="table-wrap"><table><tr><th>Agente</th><th>Alvo</th><th>Estado</th></tr>${d.tasks.map(t => `<tr><td>${esc(t.agent)}</td><td>${esc(t.target)}</td><td>${pill(t.status)}${t.error ? `<div class="mut">${esc(t.error.slice(0, 120))}</div>` : ""}</td></tr>`).join("")}</table></div>` : `<p class="mut">aguardando início</p>`}</div>
   <div class="card"><h3>Comunicação do Hacker AI</h3>${d.mensagens.length ? d.mensagens.slice(-40).map(m => `<div class="msg"><b>${esc(m.sender)}</b> <span class="mut">${esc(m.type)}</span><br>${esc(JSON.stringify(m.payload)).slice(0, 300)}</div>`).join("") : `<p class="mut">sem mensagens ainda</p>`}</div>`;
  const act = async (path) => { await api(path, {method: "POST", body: {}}); route(); };
  const jp = $("#jpause"), jc = $("#jcancel"), jr = $("#jresume");
  if (jp) jp.onclick = () => act("/api/jobs/" + id + "/pause").catch(e => alert(e.message));
  if (jc) jc.onclick = () => confirm("Cancelar tarefa #" + id + "?") && act("/api/jobs/" + id + "/cancel").catch(e => alert(e.message));
  if (jr) jr.onclick = () => act("/api/jobs/" + id + "/resume").catch(e => alert(e.message));
  if (["na_fila", "executando", "aguardando_aprovacao"].includes(j.status)) timer = setTimeout(route, 3000);
};
V.approvals = async () => {
  const as = await api("/api/approvals");
  app.innerHTML = `<h2>Aprovação de operações sensíveis</h2><p class="mut">Negar mantém só a parte passiva da missão. Toda decisão vai para a trilha de auditoria com usuário, hora e justificativa.</p>
  ${as.length ? as.map(a => `<div class="card">${pill(a.status)} <b>${esc(a.op)}</b> → ${esc(a.target)}<div class="mut">tarefa #${a.job_id} · cliente ${esc(a.client_id)} · ${esc(a.detail)} · pedido por ${esc(a.requested_by)} em ${dt(a.requested)}</div>
   ${a.status === "pendente" && owner() ? `<form class="dec" data-id="${a.id}"><label>Justificativa (obrigatória)</label><input name="reason" required><div class="row"><button class="ok" name="d" value="approve">Aprovar</button><button class="bad" name="d" value="deny">Negar</button></div><p class="err"></p></form>`
     : `<div class="mut">decidido por ${esc(a.decided_by || "—")} em ${dt(a.decided)}: ${esc(a.reason || "")}</div>`}</div>`).join("") : `<p class="card mut">Nenhuma solicitação.</p>`}`;
  document.querySelectorAll("form.dec").forEach(f => f.onsubmit = async e => { e.preventDefault();
    try { await api("/api/approvals/" + f.dataset.id, {method: "POST", body: {decision: e.submitter.value, reason: f.reason.value}}); route(); } catch (x) { f.querySelector(".err").textContent = x.message; } });
};
V.clients = async () => {
  const cl = await api("/api/clients");
  app.innerHTML = `<h2>Escopos autorizados</h2>${cl.map(c => `<div class="card"><b>${esc(c.name)}</b> ${pill(c.vigente ? "vigente" : "fora da validade")}<div class="mut">id ${esc(c.id)} · termo ${esc(c.authorization_ref)} · autorizado por ${esc(c.authorized_by)} · ${esc(c.valid_from)} a ${esc(c.valid_until)}</div>
   <div>hosts: ${c.hosts.map(esc).join(", ")}</div>${owner() ? `<button class="sec del" data-id="${esc(c.id)}">Excluir</button>` : ""}</div>`).join("") || `<p class="card mut">Nenhum cliente cadastrado.</p>`}
   ${owner() ? `<form id="f" class="card"><h3>Novo cliente (exige termo assinado)</h3>
   <label>id (ex.: padaria-exemplo)</label><input name="id" required><label>Nome</label><input name="name" required>
   <label>Referência do termo de autorização</label><input name="authorization_ref" required placeholder="TERMO-2026-001"><label>Autorizado por (nome, cargo)</label><input name="authorized_by" required>
   <label>Contato</label><input name="contact"><div class="row"><div style="flex:1"><label>Válido de</label><input name="valid_from" type="date" required></div><div style="flex:1"><label>até</label><input name="valid_until" type="date" required></div></div>
   <label>Hosts autorizados (um por linha, sem curingas)</label><textarea name="hosts" rows="3" required></textarea><button>Salvar</button><p class="err"></p>
   <p class="mut">Não coloque senhas ou chaves aqui — o servidor recusa.</p></form>` : ""}`;
  if (!owner()) return;
  document.querySelectorAll(".del").forEach(b => b.onclick = async () => { if (!confirm("Excluir cliente " + b.dataset.id + "?")) return; try { await api("/api/clients/" + b.dataset.id, {method: "DELETE"}); route(); } catch (x) { alert(x.message); } });
  form($("#f"), async d => { d.hosts = d.hosts.split(/\s+/).filter(Boolean); await api("/api/clients", {method: "POST", body: d}); route(); });
};
async function pickJob(title, sel, cb) {
  const js = (await api("/api/jobs")).filter(j => j.status === "concluida");
  app.innerHTML = `<h2>${title}</h2><div class="card"><label>Auditoria</label><select id="pj">${js.map(j => `<option value="${j.id}" ${String(j.id) === String(sel) ? "selected" : ""}>#${j.id} · ${esc(j.client_id)} · ${esc((j.goal || "").slice(0, 40))}</option>`).join("")}</select></div><div id="out"></div>`;
  if (!js.length) { $("#out").innerHTML = `<p class="card mut">Nenhuma auditoria concluída.</p>`; return; }
  $("#pj").onchange = () => cb($("#pj").value); cb($("#pj").value);
}
V.findings = async sel => pickJob("Vulnerabilidades e evidências", sel, async id => {
  const fs = await api(`/api/jobs/${id}/findings`), order = {P1: 1, P2: 2, P3: 3, P4: 4};
  fs.sort((a, b) => (order[a.severity] || 9) - (order[b.severity] || 9));
  $("#out").innerHTML = `<p class="mut">Só "confirmado" tem evidência reproduzida pelo validador; "suspeita" não é vulnerabilidade declarada.</p>` + (fs.map(f => `<details class="card"><summary>${pill(f.severity)} ${pill(f.status)} <b>${esc(f.title)}</b><div class="mut">${esc(f.target)}</div></summary>
    <p><b>Evidência:</b> ${esc(f.evidence)}</p>${f.proof && Object.keys(f.proof).length ? `<pre>${esc(JSON.stringify(f.proof, null, 1))}</pre>` : ""}<p><b>Impacto:</b> ${esc(f.impact)}</p><p><b>Recomendação:</b> ${esc(f.recommendation)}</p><p class="mut">Reproduzir: ${esc(f.repro)}</p></details>`).join("") || `<p class="card mut">Sem achados.</p>`);
});
V.compare = async () => {
  const js = (await api("/api/jobs")).filter(j => j.status === "concluida"), o = js.map(j => `<option value="${j.id}">#${j.id} · ${esc(j.client_id)} · ${esc((j.goal || "").slice(0, 30))}</option>`).join("");
  app.innerHTML = `<h2>Comparar auditorias (mesmo cliente)</h2><form id="f" class="card"><label>Antes</label><select name="a">${o}</select><label>Depois</label><select name="b">${o}</select><button>Comparar</button><p class="err"></p></form><div id="out"></div>`;
  form($("#f"), async d => { const r = await api(`/api/compare?a=${d.a}&b=${d.b}`);
    $("#out").innerHTML = [["novos", "Novos"], ["corrigidos", "Corrigidos"], ["persistentes", "Persistentes"]].map(([k, t]) => `<div class="card"><h3>${t} (${r[k].length})</h3>${r[k].map(f => `<div>${pill(f.severity)} ${esc(f.title)} <span class="mut">${esc(f.target)}</span></div>`).join("")}</div>`).join(""); });
};
V.reports = async () => {
  const js = (await api("/api/jobs")).filter(j => j.status === "concluida"); let h = "";
  for (const j of js.slice(0, 30)) { const d = await api("/api/jobs/" + j.id); d.arquivos.filter(f => f.endsWith(".pdf")).forEach(f => h += `<div class="card row"><div style="flex:1"><b>#${j.id}</b> ${esc(j.client_id)} · ${esc((j.goal || "").slice(0, 40))}</div><a class="btn sec" href="#/pdf/${j.id}/${esc(f)}">Ver</a><a class="btn" href="/api/jobs/${j.id}/files/${encodeURIComponent(f)}?dl=1">Baixar</a></div>`); }
  app.innerHTML = `<h2>Relatórios PDF</h2>${h || `<p class="card mut">Nenhum PDF ainda.</p>`}`;
};
V.pdf = async (id, f) => { app.innerHTML = `<h2>PDF da tarefa #${esc(id)}</h2><div class="row" style="margin-bottom:8px"><a class="btn" href="/api/jobs/${esc(id)}/files/${encodeURIComponent(f)}?dl=1">Baixar</a></div><iframe title="PDF" src="/api/jobs/${esc(id)}/files/${encodeURIComponent(f)}"></iframe>`; };
V.tools = async () => {
  const t = await api("/api/tools");
  app.innerHTML = `<h2>Ferramentas e módulos</h2><form id="f" class="card"><h3>Ferramentas externas (OSS)</h3>${t.ferramentas.map(x => `<div class="row"><label style="flex:1">${esc(x.nome)} ${pill(x.instalada ? "instalada" : "ausente")}</label>${owner() ? `<label><input type="checkbox" name="off" value="${esc(x.nome)}" ${x.desativada ? "checked" : ""} style="width:auto"> desativar</label>` : ""}</div>`).join("")}
   ${owner() ? `<button>Salvar</button><p class="err"></p><p class="mut">Instalar ferramentas é alteração de sistema: feita fora do app (scripts/fetch_labs.sh), nunca por aqui.</p>` : ""}</form>
   <div class="card"><h3>Laboratórios</h3>${t.laboratorios.map(l => `<div>${pill(l.estado)} <b>${esc(l.nome)}</b> <span class="mut">${esc(l.descricao)} ${esc(l.motivo || "")}</span></div>`).join("")}</div>
   <div class="card"><h3>Agentes registrados (${t.agentes.length})</h3><table>${t.agentes.map(a => `<tr><td>${esc(a.nome)}</td><td class="mut">${esc(a.descricao)}</td></tr>`).join("")}</table></div>`;
  if (owner()) form($("#f"), async () => { await api("/api/tools", {method: "POST", body: {disabled: [...document.querySelectorAll("input[name=off]:checked")].map(i => i.value)}}); route(); });
};
V.logs = async () => {
  const a = await api("/api/audit?limit=150"), m = await api("/api/monitor");
  app.innerHTML = `<h2>Logs e monitoramento</h2><div class="card">Trilha de auditoria (hash encadeado): ${a.integra ? pill("íntegra") : `<span class="pill erro">alterada na linha ${a.linha_quebrada}</span>`}<div class="mut">uptime ${m.uptime_s}s · workers ${m.workers_vivos}/${m.workers_total} · fila ${m.fila} · banco ${m.db_kb} KB · disco livre ${m.disco_livre_gb} GB</div></div>
   <div class="card"><table><tr><th>Quando</th><th>Evento</th><th>Detalhe</th></tr>${a.eventos.map(e => { const {ts, op, prev, hash, ...r} = e; return `<tr><td class="mut">${esc(ts)}</td><td>${esc(op)}</td><td class="mut">${esc(JSON.stringify(r)).slice(0, 160)}</td></tr>`; }).join("")}</table></div></div>`;
  timer = setTimeout(route, 8000);
};
V.finance = async () => {
  const f = await api("/api/finance"), cl = await api("/api/clients"), t = f.totais_centavos;
  app.innerHTML = `<h2>Financeiro e comercial</h2><p class="mut">Somente lançamentos manuais; o app não calcula nem estima receita.</p>
   <div class="grid"><div class="card kpi"><b>${brl(t.receita)}</b><span>Receitas</span></div><div class="card kpi"><b>${brl(t.despesa)}</b><span>Despesas</span></div><div class="card kpi"><b>${brl(f.saldo_centavos)}</b><span>Saldo</span></div><div class="card kpi"><b>${brl(t.proposta)}</b><span>Propostas em aberto</span></div></div>
   <div class="card">${f.lancamentos.length ? `<div class="table-wrap"><table><tr><th>Data</th><th>Tipo</th><th>Descrição</th><th>Valor</th><th></th></tr>${f.lancamentos.map(r => `<tr><td>${esc(r.date)}</td><td>${esc(r.kind)}</td><td>${esc(r.description)} <span class="mut">${esc(r.client_id || "")} ${esc(r.status || "")}</span></td><td>${brl(r.amount_cents)}</td><td>${owner() ? `<button class="sec del" data-id="${r.id}">x</button>` : ""}</td></tr>`).join("")}</table></div>` : `<p class="mut">Nenhum lançamento.</p>`}</div>
   ${owner() ? `<form id="f" class="card"><h3>Novo lançamento</h3><label>Data</label><input type="date" name="date" required><label>Tipo</label><select name="kind"><option>receita</option><option>despesa</option><option>proposta</option></select>
   <label>Cliente (opcional)</label><select name="client_id"><option value="">—</option>${cl.map(c => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join("")}</select><label>Descrição</label><input name="description" required><label>Valor (R$)</label><input name="amount" type="number" step="0.01" min="0" required><label>Situação</label><input name="status" placeholder="pago, enviado, aceito…"><button>Adicionar</button><p class="err"></p></form>` : ""}`;
  if (!owner()) return;
  document.querySelectorAll(".del").forEach(b => b.onclick = async () => { await api("/api/finance/" + b.dataset.id, {method: "DELETE"}); route(); });
  form($("#f"), async d => { await api("/api/finance", {method: "POST", body: d}); route(); });
};
async function route() {
  clearTimeout(timer); const [, page = "dashboard", ...args] = (location.hash || "#/dashboard").split("/");
  if (!ME && page !== "login") { try { ME = await api("/api/me"); } catch (e) { return; } }
  navbar(page); $("#nav").classList.remove("open");
  try { await (V[page] || V.dashboard)(...args.map(decodeURIComponent)); } catch (e) { if (ME) app.innerHTML = `<p class="card err">${esc(e.message)}</p>`; }
}
window.addEventListener("hashchange", route); route();
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js", {scope: "/"}).catch(() => {});
let deferred; window.addEventListener("beforeinstallprompt", e => { e.preventDefault(); deferred = e; $("#install").hidden = false; });
$("#install").onclick = async () => { if (deferred) { deferred.prompt(); deferred = null; $("#install").hidden = true; } };

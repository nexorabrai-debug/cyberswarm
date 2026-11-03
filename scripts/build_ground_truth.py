"""Builds cyberswarm/extval/data/gt_*.json from the projects' OFFICIAL lists (downloaded by fetch_labs.sh). Not written by us:
we only copy names/ids and record the source link. Our only decisions are documented in 'nota'."""
import json, os, re, sys, zipfile
L = os.environ.get("CYBERSWARM_LABS", os.path.expanduser("~/labs")); OUT = os.path.join(os.path.dirname(__file__), "..", "cyberswarm", "extval", "data")
def save(name, d): json.dump(d, open(os.path.join(OUT, f"gt_{name}.json"), "w"), indent=1, ensure_ascii=False); print(name, len(d["items"]))
def md_bullets(path, start, stop):
    t = open(path).read(); t = t[t.index(start):]; t = t[:t.index(stop)] if stop in t else t
    return [m.strip() for m in re.findall(r"(?m)^\s*[*-] (?!\*\*)(.+)$", t)]
# Juice Shop: data/static/challenges.yml
t = open(os.path.join(L, "juice-shop/data/static/challenges.yml")).read(); items = []
for block in re.split(r"(?m)^-\s*$", t)[1:]:
    g = lambda k: (re.search(rf"(?m)^  {k}: ['\"]?(.*?)['\"]?\s*$", block) or [None, ""])[1]
    if g("key"): items.append({"id": g("key"), "name": g("name"), "category": g("category"), "difficulty": g("difficulty")})
save("juice-shop", {"lab": "juice-shop", "version": "v20.3.0", "source": "https://github.com/juice-shop/juice-shop/blob/v20.3.0/data/static/challenges.yml", "items": items,
                    "nota": "Todos os desafios oficiais (inclui os que exigem interação ativa)."})
# WebGoat: lesson packages in the official jar
z = zipfile.ZipFile(os.path.join(L, "webgoat.jar")); pk = set()
for n in z.namelist():
    m = re.search(r"org/owasp/webgoat/lessons/([a-z0-9_]+)/", n)
    if m: pk.add(m.group(1))
NONVULN = {"lessontemplate", "webgoatintroduction", "webwolfintroduction", "httpbasics", "httpproxies", "chromedevtools", "cia"}
save("webgoat", {"lab": "webgoat", "version": "v2026.4", "source": "https://github.com/WebGoat/WebGoat/tree/v2026.4/src/main/java/org/owasp/webgoat/lessons",
                 "items": [{"id": p, "name": p} for p in sorted(pk - NONVULN)],
                 "nota": f"Lições oficiais do jar. Removidas por NÓS (não são vulnerabilidades, são tutoriais): {sorted(NONVULN)}"})
save("vampi", {"lab": "vampi", "version": "f16052d", "source": "https://github.com/erev0s/VAmPI#list-of-vulnerabilities",
               "items": [{"id": re.sub(r"\W+", "_", x.lower()).strip("_"), "name": x} for x in md_bullets(os.path.join(L, "VAmPI/README.md"), "#### List of Vulnerabilities", "## Run it")]})
dv = []; cat = ""
t = open(os.path.join(L, "dvga/README.md")).read(); t = t[t.index("* **Reconnaissance**"):]; t = t[:t.index("\n\n")]
for l in t.splitlines():
    m = re.match(r"\* \*\*(.+)\*\*", l.strip())
    if m: cat = m.group(1); continue
    if l.strip().startswith("* "): n = l.strip()[2:]; dv.append({"id": re.sub(r"\W+", "_", n.lower()).strip("_"), "name": n, "category": cat})
save("dvga", {"lab": "dvga", "version": "a961308", "source": "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application#scenarios", "items": dv})
ib = md_bullets(os.path.join(L, "ibsrc/README.markdown"), "The list of vulnerabilities", "Below are some of the other")
save("insecurebankv2", {"lab": "insecurebankv2", "version": "3c8cc3a", "source": "https://github.com/dineshshetty/Android-InsecureBankv2#readme",
                        "items": [{"id": re.sub(r"\W+", "_", x.lower()).strip("_"), "name": x} for x in ib],
                        "nota": "Só a lista 'currently included' (a lista 'working on' foi excluída, pois o próprio autor diz que ainda não está no app)."})
cr = re.findall(r"(?m)^### Challenge (\d+) - (.+)$", open(os.path.join(L, "crapi/docs/challenges.md")).read())
save("crapi", {"lab": "crapi", "version": "git", "source": "https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md",
               "items": [{"id": f"challenge_{n}", "name": s.strip()} for n, s in cr], "nota": "Não executado (exige Docker; ver VALIDACAO_EXTERNA.md)."})

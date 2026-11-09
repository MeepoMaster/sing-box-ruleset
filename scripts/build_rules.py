#!/usr/bin/env python3
"""构建 sing-box 规则集 JSON —— 大列表友好版（所有热路径均为 C 级原语）。"""
import json, os, re, time
from pathlib import Path

TMP      = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
SRC      = Path("source")
BUILD    = TMP / "build"
UP       = TMP / "up"
VER      = int(os.environ["EFFECTIVE_VERSION"])
PRODUCTS    = os.environ.get("PRODUCTS", "emby app adg-awa adg-dns cn").split()
WHITELISTED = os.environ.get("WHITELISTED", "emby adg-awa adg-dns").split()
BIG         = int(os.environ.get("BIG_ARRAY", "20000"))

BUILD.mkdir(parents=True, exist_ok=True)
_T0 = time.time()
def log(msg):
    print("[%6.1fs] %s" % (time.time() - _T0, msg), flush=True)

LABEL = {"domain:": "domain", "domain：": "domain",
         "domain_suffix:": "suffix", "domain_suffix：": "suffix",
         "domain_keyword:": "keyword", "domain_keyword：": "keyword",
         "domain_regex:": "regex", "domain_regex：": "regex"}
TITLE = {"domain": "domain:", "suffix": "domain_suffix:",
         "keyword": "domain_keyword:", "regex": "domain_regex:"}
ORDER    = ("domain", "suffix", "keyword", "regex")
DOM_KEYS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
HOST_KEYS = ("domain", "domain_suffix", "domain_keyword")
NOTES    = {}

def note(key, msg):
    NOTES.setdefault(key, []).append(msg)

def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)

_SAFE = re.compile(r'["\\\x00-\x1f]')

def _arr_lines(key, vals, ind):
    """一个数组渲染成 数组双方括号+每项一行，与 jq . 输出一致"""
    kp = " " * ind
    ep = " " * (ind + 2)
    if not vals:
        return ['%s"%s": []' % (kp, key)]
    if _SAFE.search("".join(vals)) is None:
        body = ep + '"' + ('",\n' + ep + '"').join(vals) + '"'
    else:
        body = ep + (",\n" + ep).join(json.dumps(x, ensure_ascii=False) for x in vals)
    return ['%s"%s": [' % (kp, key), body, kp + "]"]

def dump(path, doc):
    out = ["{", '  "version": %d,' % doc["version"], '  "rules": [']
    rules = doc.get("rules") or []
    for ri, rule in enumerate(rules):
        out.append("    {")
        items = list(rule.items())
        for i, (k, v) in enumerate(items):
            tail = "," if i < len(items) - 1 else ""
            if isinstance(v, list):
                lines = _arr_lines(k, v, 6)
                lines[-1] += tail
                out.extend(lines)
            else:
                out.append('      "%s": %s%s' % (k, json.dumps(v, ensure_ascii=False), tail))
        out.append("    }" + ("," if ri < len(rules) - 1 else ""))
    out += ["  ]", "}"]
    Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")

# ---------- 两个 C 级匹配原语 ----------
def covered_by(host, sset):
    """host 自身或其任一父域在 sset 里"""
    if host in sset:
        return True
    i = host.find(".")
    while i != -1:
        if host[i + 1:] in sset:
            return True
        i = host.find(".", i + 1)
    return False

def covered_by_parent(host, sset):
    """host 的父域在 sset 里（不含自身）"""
    i = host.find(".")
    while i != -1:
        if host[i + 1:] in sset:
            return True
        i = host.find(".", i + 1)
    return False

# ---------- TXT ----------
def parse_txt(p, default):
    groups = {k: [] for k in ORDER}
    cur, tagged = default, False
    if not Path(p).exists():
        return groups, tagged
    for raw in Path(p).read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        hit = LABEL.get(s.lower())
        if hit:
            cur, tagged = hit, True
            continue
        groups[cur].append(s)
    return groups, tagged

def tidy_hosts(name, default):
    p = SRC / name
    groups, tagged = parse_txt(p, default)
    if not any(groups.values()):
        return groups
    for k in ORDER:
        if groups[k]:
            groups[k] = sorted(set(groups[k])) if k == "regex" \
                else sorted({v.lower() for v in groups[k]})
    if tagged:
        blocks = ["%s\n%s" % (TITLE[k], "\n".join(groups[k])) for k in ORDER if groups[k]]
        p.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")
    else:
        p.write_text("\n".join(groups[default]) + "\n", encoding="utf-8")

    bad = [v for k in ("domain", "suffix", "keyword") for v in groups[k]
           if re.search(r"[*^/\\: ]", v)]
    if bad:
        note(name, "疑似非法条目（含 * / ^ : 空格）：%s" % "、".join(bad[:5]))

    suf = groups["suffix"]
    if suf and len(suf) < BIG:
        sset = set(suf)
        inner = [s for s in suf if covered_by_parent(s, sset)]
        if inner:
            note(name, "有 %d 条后缀被同文件更宽的后缀覆盖（产物自动去掉，输入可自行清理）：%s"
                 % (len(inner), "、".join(inner[:6])))
    log("%s：domain=%d suffix=%d keyword=%d"
        % (name, len(groups["domain"]), len(groups["suffix"]), len(groups["keyword"])))
    return groups

def tidy_flat(name):
    p = SRC / name
    if not p.exists():
        return []
    vals = sorted({l.strip() for l in p.read_text(encoding="utf-8").splitlines()
                   if l.strip() and not l.lstrip().startswith("#")})
    p.write_text("\n".join(vals) + "\n", encoding="utf-8")
    log("%s：%d 条" % (name, len(vals)))
    return vals

# ---------- 归一化（体积分级） ----------
def norm_rule(rule, name):
    for k in DOM_KEYS:
        v = rule.get(k)
        if not isinstance(v, list):
            continue
        if len(v) >= BIG:
            rule[k] = sorted({x for x in v if isinstance(x, str)})
            note(name, "%s 共 %d 条，已跳过冗余裁剪以控制耗时（不影响匹配结果）" % (k, len(v)))
            continue
        rule[k] = sorted({str(x).strip() for x in v if str(x).strip()})

    sufs = rule.get("domain_suffix", [])
    if sufs and len(sufs) < BIG:
        sset = set(sufs)
        drop = {s for s in sufs if covered_by_parent(s, sset)}
        if drop:
            note(name, "后缀被更宽后缀覆盖，去掉 %d 条（如 %s）"
                 % (len(drop), "、".join(sorted(drop)[:4])))
        rule["domain_suffix"] = [s for s in sufs if s not in drop]

    kws = rule.get("domain_keyword", [])
    if kws and len(kws) < BIG:
        drop = {t for t in kws if any(t != u and u in t for u in kws)}
        if drop:
            note(name, "关键词被更短关键词覆盖，去掉 %d 条" % len(drop))
        rule["domain_keyword"] = [t for t in kws if t not in drop]

    dom = rule.get("domain", [])
    if dom and len(dom) + len(rule.get("domain_suffix", [])) < BIG:
        sset = set(rule.get("domain_suffix", []))
        kws  = rule.get("domain_keyword", [])
        drop = {d for d in dom if covered_by(d, sset) or any(k in d for k in kws)}
        if drop:
            note(name, "domain 被 suffix/keyword 覆盖，去掉 %d 条（如 %s）"
                 % (len(drop), "、".join(sorted(drop)[:4])))
        rule["domain"] = [d for d in dom if d not in drop]

    for k in DOM_KEYS:
        if k in rule and not rule[k]:
            del rule[k]
    return rule

def norm_doc(doc, name):
    if not doc.get("rules"):
        doc["rules"] = [{}]
    for rule in doc["rules"]:
        norm_rule(rule, name)
    doc["version"] = VER
    return doc

# ---------- 白名单（C 级批量后缀匹配） ----------
class Whitelist:
    def __init__(self, g):
        self.dom = set(g.get("domain") or [])
        self.suf = set(g.get("suffix") or [])
        self.kw  = set(g.get("keyword") or [])
        self.tup = tuple("." + x for x in self.suf)
        self.used, self.hits, self.conflicts = set(), 0, []
        self.coarse = False

    def keep(self, arr):
        if not (self.dom or self.suf or self.kw) or not arr:
            return arr
        if self.kw:
            keep = [x for x in arr
                    if not (x in self.dom or x in self.suf
                            or (self.tup and x.endswith(self.tup))
                            or any(k in x for k in self.kw))]
        else:
            keep = [x for x in arr
                    if not (x in self.dom or x in self.suf
                            or (self.tup and x.endswith(self.tup)))]
        self.hits += len(arr) - len(keep)
        if len(arr) < BIG:
            for ent in list(self.dom) + list(self.suf):
                if any(h == ent or (self.tup and h.endswith("." + ent)) for h in arr):
                    self.used.add(ent)
            for k in self.kw:
                if any(k in h for h in arr):
                    self.used.add(k)
        else:
            self.coarse = True
        return keep

    def find_conflicts(self, block_suffix):
        for x in sorted(self.dom | self.suf):
            i = x.find(".")
            while i != -1:
                p = x[i + 1:]
                if p in block_suffix:
                    self.conflicts.append((x, p))
                    break
                i = x.find(".", i + 1)

    def report(self):
        entries = (["domain:" + x for x in sorted(self.dom)]
                   + ["suffix:" + x for x in sorted(self.suf)]
                   + ["keyword:" + x for x in sorted(self.kw)])
        unused = [] if self.coarse else [e for e in entries if e.split(":", 1)[1] not in self.used]
        return {"entries": len(entries), "removed": self.hits, "unused": unused,
                "conflicts": sorted(set(self.conflicts)), "coarse": self.coarse}

def apply_wl(rule, wl, name):
    before = wl.hits
    for key in ("domain", "domain_suffix", "domain_keyword"):
        if rule.get(key):
            rule[key] = wl.keep(rule[key])
    removed = wl.hits - before
    if removed:
        note(name, "白名单剔除 %d 条（noblock.txt 优先）" % removed)

# ---------- 组装 ----------
def clone_rule(sr):
    r = dict(sr)
    for k in HOST_KEYS:
        if k in sr:
            r[k] = list(sr.get(k) or [])
    return r

def merge(rule, g, keys=HOST_KEYS):
    for gk, rk in (("domain", "domain"), ("suffix", "domain_suffix"), ("keyword", "domain_keyword")):
        if gk in keys and g.get(gk):
            rule[rk] = list(rule.get(rk) or []) + list(g[gk])

_CACHE = {}
def load_up(name):
    if name not in _CACHE:
        _CACHE[name] = load(UP / name)
    return _CACHE[name]

def pick(name, ups):
    if ups and all((UP / u).is_file() for u in ups):
        try:
            docs = [load_up(u) for u in ups]
            if all(isinstance(d.get("rules"), list) for d in docs):
                return docs, "upstream"
        except Exception as e:
            note(name, "上游解析失败：%s" % e)
    prev = SRC / ("%s.json" % name)
    if prev.is_file():
        note(name, "⚠️ 上游不可用，回退到上一次产物（本次未更新上游内容）")
        log("%s：回退到 source/%s.json" % (name, name))
        return [load(prev)], "previous"
    raise SystemExit("[%s] 上游与历史产物都不可用" % name)

def delta(name, rule):
    prev = SRC / ("%s.json" % name)
    if not prev.is_file():
        return "新建"
    try:
        old = load(prev)["rules"][0]
    except Exception:
        return "-"
    add = rem = 0
    for k in HOST_KEYS:
        a, b = set(rule.get(k) or []), set(old.get(k) or [])
        add += len(a - b); rem += len(b - a)
    return "+%d/−%d" % (add, rem)

def write_summary(rep, path):
    oc = {"upstream": "上游", "previous": "⚠️ 回退（旧产物）", "local": "本地"}
    md = ["## 规则集构建结果（v%s）" % rep["version"], "",
          "| 产物 | 来源 | domain | domain_suffix | domain_keyword | domain_regex | 变更 |",
          "| --- | --- | ---: | ---: | ---: | ---: | --- |"]
    for name, info in rep["products"].items():
        c = info["counts"]
        md.append("| %s | %s | %d | %d | %d | %d | %s |" % (
            name, oc.get(info["origin"], info["origin"]),
            c["domain"], c["domain_suffix"], c["domain_keyword"], c["domain_regex"],
            info.get("delta", "")))
    pn = ["- **%s**：%s" % (n, w) for n, i in rep["products"].items() for w in i["notes"]]
    fn = ["- **%s**：%s" % (n, w) for n, ws in rep["files"].items() for w in ws]
    md += ["", "<details><summary>归一化提示</summary>", ""] + (pn + fn or ["- 无"]) + ["", "</details>"]

    w = rep["whitelist"]
    md += ["", "<details><summary>白名单（noblock.txt）</summary>", "",
           "- 条目 %d 条，本次剔除 %d 条" % (w["entries"], w["removed"])]
    if w["unused"]:
        md.append("- 未命中任何条目（拼写有误或上游已不含）：%s" % "、".join(w["unused"]))
    elif w["coarse"]:
        md.append("- 上游列表过大，未逐条统计白名单命中情况")
    if w["conflicts"]:
        md.append("- ⚠️ 冲突：白名单项被更宽的封禁后缀盖住，无法逐条放行：")
        md += ["  - `%s` ⊂ `%s`（请拆分该后缀）" % (x, s) for x, s in w["conflicts"]]
    md += ["", "</details>", ""]
    path.write_text("\n".join(md) + "\n", encoding="utf-8")

def main():
    log("开始：v%s，产物 %s，BIG_ARRAY=%d" % (VER, " ".join(PRODUCTS), BIG))
    block    = tidy_hosts("block.txt", "domain")
    noblock  = tidy_hosts("noblock.txt", "domain")
    cn_local = tidy_hosts("cn.txt", "suffix")
    procs    = tidy_flat("process.txt")
    wl = Whitelist(noblock)
    log("白名单：domain=%d suffix=%d keyword=%d（后缀元组 %d 项）"
        % (len(wl.dom), len(wl.suf), len(wl.kw), len(wl.tup)))

    out = {}
    p = SRC / "emby.json"
    if not p.is_file():
        raise SystemExit("缺少 source/emby.json")
    doc = load(p)
    if "emby" in WHITELISTED:
        apply_wl(doc["rules"][0] if doc.get("rules") else {}, wl, "emby")
    out["emby"] = (norm_doc(doc, "emby"), "local")

    docs, origin = pick("adg-awa", ["awa.json"])
    doc = {"rules": [clone_rule(docs[0]["rules"][0])]}
    merge(doc["rules"][0], block)
    if "adg-awa" in WHITELISTED:
        apply_wl(doc["rules"][0], wl, "adg-awa")
    out["adg-awa"] = (norm_doc(doc, "adg-awa"), origin)

    docs, origin = pick("adg-dns", ["awa.json", "adblock.json"])
    if origin == "upstream" and len(docs) == 2:
        doc = {"rules": [{}]}
        for d in docs:
            merge(doc["rules"][0], {"domain": (d["rules"][0].get("domain") or []),
                                    "suffix": (d["rules"][0].get("domain_suffix") or []),
                                    "keyword": (d["rules"][0].get("domain_keyword") or [])})
    else:
        doc = {"rules": [clone_rule(docs[0]["rules"][0])]}
    merge(doc["rules"][0], block)
    if "adg-dns" in WHITELISTED:
        apply_wl(doc["rules"][0], wl, "adg-dns")
    out["adg-dns"] = (norm_doc(doc, "adg-dns"), origin)

    docs, origin = pick("app", ["applications.json"])
    doc = {"rules": [clone_rule(docs[0]["rules"][0])]}
    if procs:
        rule = doc["rules"][0]
        exist = [str(x).strip() for x in (rule.get("process_name") or []) if str(x).strip()]
        rule["process_name"] = sorted(set(exist) | set(procs))
    out["app"] = (norm_doc(doc, "app"), origin)

    docs, origin = pick("cn", ["cn.json"])
    doc = {"rules": [clone_rule(docs[0]["rules"][0])]}
    merge(doc["rules"][0], cn_local)
    out["cn"] = (norm_doc(doc, "cn"), origin)

    log("产物组装完成，开始校验/落盘")
    all_suf = set()
    report = {"version": VER, "products": {}, "files": NOTES}
    for name in PRODUCTS:
        if name not in out:
            raise SystemExit("未知产物：%s" % name)
        doc, origin = out[name]
        rule = doc["rules"][0]
        all_suf |= set(rule.get("domain_suffix") or [])

        if rule.get("domain") and rule.get("domain_suffix"):
            sset = set(rule["domain_suffix"])
            cross = sum(1 for d in rule["domain"] if covered_by(d, sset))
            if cross:
                raise SystemExit("[%s] 仍有 %d 条 domain 被 domain_suffix 覆盖" % (name, cross))

        dump(BUILD / ("%s.json" % name), doc)
        counts = {k: len(rule.get(k, [])) for k in DOM_KEYS}
        log("%s ← %s：domain=%d suffix=%d keyword=%d regex=%d"
            % (name, origin, counts["domain"], counts["domain_suffix"],
               counts["domain_keyword"], counts["domain_regex"]))
        report["products"][name] = {"origin": origin, "counts": counts,
                                    "delta": delta(name, rule),
                                    "notes": NOTES.get(name, [])}

    wl.find_conflicts(all_suf)
    report["whitelist"] = wl.report()
    dump(BUILD / "report.json", report)
    write_summary(report, BUILD / "summary.md")
    log("完成")

if __name__ == "__main__":
    main()

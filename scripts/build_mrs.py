#!/usr/bin/env python3
"""把 build_rules.py 的产物转成 mihomo mrs 的中间文本（与 sing-box 同源）。

域名映射：
  domain_suffix  ->  +.x     (自身 + 子域)
  domain         ->  x       (mrs 只有后缀语义，会被放宽为后缀，报告中计数)
  domain_keyword ->  跳过    (mrs 不支持)

IP 映射：
  ChinaMax_IP.txt -> 每行一个裸 CIDR（自动剥离 IP-CIDR,/no-resolve）

产出：$RUNNER_TEMP/mrs/{emby,adg-awa,adg-dns,cn}.txt、cnip.txt、report.json
"""
import json, os, re, time
from pathlib import Path

TMP   = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
BUILD = TMP / "build"
OUT   = TMP / "mrs"
DOMAIN_PRODUCTS = os.environ.get("PRODUCTS_DOMAIN", "emby adg-awa adg-dns cn").split()

OUT.mkdir(parents=True, exist_ok=True)
_T0 = time.time()
def log(m): print("[%6.1fs] %s" % (time.time() - _T0, m), flush=True)

V4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,32}$")
V6 = re.compile(r"^[0-9a-fA-F:.]+/\d{1,128}$")

def parse_cidr(line):
    parts = [p.strip() for p in line.split(",")]
    if parts and parts[0].upper().startswith("IP-CIDR"):
        parts = parts[1:]
    if not parts:
        return None
    c = parts[0]
    if V4.match(c) or V6.match(c):
        return c.lower()
    return None

def main():
    report = {"domain": {}, "ipcidr": {}, "version": None}

    for name in DOMAIN_PRODUCTS:
        p = BUILD / ("%s.json" % name)
        if not p.is_file():
            raise SystemExit("缺少 %s（请先运行 scripts/build_rules.py）" % p)
        doc = json.loads(p.read_text(encoding="utf-8"))
        report["version"] = doc.get("version")
        rule = (doc.get("rules") or [{}])[0]
        arr = []
        arr += list(rule.get("domain") or [])
        arr += ["+." + s for s in (rule.get("domain_suffix") or [])]
        uniq = sorted(set(arr))
        (OUT / ("%s.txt" % name)).write_text("\n".join(uniq) + "\n", encoding="utf-8")
        kw = len(rule.get("domain_keyword") or [])
        report["domain"][name] = {
            "lines":  len(uniq),
            "exact":  len(rule.get("domain") or []),
            "suffix": len(rule.get("domain_suffix") or []),
            "keyword_skipped": kw,
        }
        log("domain/%s.txt：%d 行（精确 %d 放宽为后缀 / 后缀 %d / 跳过关键词 %d）"
            % (name, len(uniq), len(rule.get("domain") or []),
               len(rule.get("domain_suffix") or []), kw))

    raw = TMP / "ChinaMax_IP.txt"
    if not raw.is_file():
        raise SystemExit("缺少 %s" % raw)
    v4, v6, bad = [], [], 0
    for line in raw.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        c = parse_cidr(s)
        if c is None:
            bad += 1
            continue
        (v6 if ":" in c else v4).append(c)
    allc = sorted(set(v4) | set(v6))
    if not allc:
        raise SystemExit("cnip 为空，上游可能已变更")
    (OUT / "cnip.txt").write_text("\n".join(allc) + "\n", encoding="utf-8")
    report["ipcidr"] = {"lines": len(allc), "v4": len(set(v4)),
                        "v6": len(set(v6)), "invalid": bad}
    log("ipcidr/cnip.txt：%d 行（v4 %d / v6 %d，无效跳过 %d）"
        % (len(allc), len(set(v4)), len(set(v6)), bad))

    (OUT / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    log("完成")

if __name__ == "__main__":
    main()

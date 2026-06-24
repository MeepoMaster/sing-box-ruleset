import urllib.request
import json
import os
import re

# ==========================================
# 1. 配置上游源 (全量 16 个规则源)
# ==========================================
TXT_SOURCES = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",      # 1. AdGuard Base filter
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt", # 2. AdGuard Chinese filter
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",    # 3. AdGuard Mobile Ads filter
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",                                         # 4. AdGuard DNS filter
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",                                           # 5. AdRules DNS List
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",                                # 6. CJX's Annoyance List
    "https://easylist-downloads.adblockplus.org/easylist.txt",                                                    # 7. EasyList
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",                                               # 8. EasyList China
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",                                                 # 9. EasyPrivacy
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",                                  # 10. xinggsf mv
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",                                        # 11. jiekouAD
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",                 # 12. AWAvenue Ads Rule
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",                             # 13. DNS-Blocklists Light
    "https://abp.oisd.nl/basic/",                                                                                 # 14. OISD Basic
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",                                           # 15. StevenBlack hosts
    "https://someonewhocares.org/hosts/hosts"                                                                     # 16. Pollock hosts
]

JSON_SOURCES = [
    # 既然 16 个源全都是 TXT 格式，JSON 数组保持为空即可，代码会自动跳过
]

# ==========================================
# 2. 核心解析逻辑
# ==========================================
def fetch_content(url):
    print(f"Fetching: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return ""

def load_local_list(filepath):
    local_set = set()
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                val = line.strip()
                if val and not val.startswith('#'):
                    local_set.add(val)
    return local_set

def parse_adblock_rule(line):
    """
    解析 AdBlock 规则，剥离修饰符，提取纯域名。
    返回: (domain, is_whitelist) 或 (None, None)
    """
    line = line.strip()
    # 排除空行和普通注释
    if not line or line.startswith('!') or line.startswith('#') or line.startswith('['):
        return None, None

    # 1. 匹配标准 Adblock 语法: @@||example.com^$important 或者 ||example.com^
    match = re.match(r'^(\@\@)?\|\|([a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-]+)\^?(?:\$.*)?$', line)
    if match:
        is_whitelist = bool(match.group(1))
        domain = match.group(2)
        # 抛弃带通配符的复杂规则，我们只提取明确的域名给 sing-box 的 domain_suffix 使用
        if '*' not in domain and '/' not in domain:
            return domain, is_whitelist

    # 2. 兼容传统的 hosts 文件格式 (如: 0.0.0.0 ad.example.com)
    if line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1]
            if domain not in ['localhost', 'localhost.localdomain', 'local', '0.0.0.0']:
                return domain, False # hosts 黑名单

    return None, None

# ==========================================
# 3. 主流程控制
# ==========================================
def main():
    domain_suffixes = set()
    upstream_whitelist = set()

    print("=== 开始拉取并解析上游 TXT 规则 ===")
    for url in TXT_SOURCES:
        content = fetch_content(url)
        if not content:
            continue
        for line in content.splitlines():
            domain, is_whitelist = parse_adblock_rule(line)
            if domain:
                if is_whitelist:
                    upstream_whitelist.add(domain)
                else:
                    domain_suffixes.add(domain)

    print("=== 开始拉取并解析上游 JSON 规则 ===")
    for url in JSON_SOURCES:
        content = fetch_content(url)
        if content:
            try:
                data = json.loads(content)
                for rule in data.get("rules", []):
                    if "domain_suffix" in rule:
                        domain_suffixes.update(rule["domain_suffix"])
                    if "domain" in rule:
                        domain_suffixes.update(rule["domain"])
            except Exception as e:
                print(f"  [!] JSON Parse Error for {url}: {e}")

    print("=== 应用本地自定义规则 ===")
    local_block = load_local_list("source/block.txt")
    local_noblock = load_local_list("source/noblock.txt")

    # 逻辑合并（这是去重的关键步骤）
    print(f"处理前黑名单数量 (含重复及冲突): {len(domain_suffixes)}")
    
    # 1. 剔除上游明确标记的白名单（防止防误杀规则失效）
    domain_suffixes.difference_update(upstream_whitelist)
    
    # 2. 强制加入你个人的黑名单
    domain_suffixes.update(local_block)
    
    # 3. 强制剔除你个人的白名单
    domain_suffixes.difference_update(local_noblock)

    print(f"处理后最终拦截数量: {len(domain_suffixes)}")

    # ==========================================
    # 4. 生成终极 JSON
    # ==========================================
    final_rule = {}
    if domain_suffixes:
        final_rule["domain_suffix"] = sorted(list(domain_suffixes))

    output_json = {
        "version": 3,
        "rules": [final_rule] if final_rule else []
    }

    output_path = "source/adg-dns.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_json, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 成功生成 {output_path}！")

if __name__ == "__main__":
    main()

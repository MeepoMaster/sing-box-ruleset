import urllib.request
import json
import os
import re
import ipaddress
import concurrent.futures

# ==========================================
# 1. 配置上游源 
# ==========================================
TXT_SOURCES = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",      
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt", 
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",    
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",                                         
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",                                           
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",                                
    "https://easylist-downloads.adblockplus.org/easylist.txt",                                                    
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",                                               
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",                                                 
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",                                  
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",                                        
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",                 
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",                             
    "https://abp.oisd.nl/basic/",                                                                                 
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",                                           
    "https://someonewhocares.org/hosts/hosts"                                                                     
]

AUTHOR_FILES = [
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/white.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/myblock.txt"
]

JSON_SOURCES = []

# ==========================================
# 2. 核心解析与校验逻辑 
# ==========================================
def is_valid_domain(domain):
    if not domain or '.' not in domain or len(domain) < 4:
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    if not re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$', domain):
        return False
        
    invalid_tlds = {
        'js', 'gif', 'jpg', 'jpeg', 'png', 'css', 'php', 'svg', 
        'woff', 'woff2', 'ttf', 'eot', 'mp3', 'mp4', 'avi', 'mkv',
        'json', 'xml', 'csv', 'txt', 'html', 'htm', 'md', 'pdf',
        'webp', 'ts', 'm3u8', 'swf', 'ico', 'apk', 'exe', 'zip', 'gz',
        'action', 'do', 'jsp', 'asp', 'aspx'
    }
    
    tld = domain.split('.')[-1].lower()
    if tld in invalid_tlds:
        return False
    return True

def parse_adblock_rule(line):
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#') or line.startswith('['):
        return None, None, None

    # 【精髓修复】：去掉了 (?:\$.*)?$ ，严格拒绝任何带有 $ 修饰符的复杂规则，彻底斩断对 baidu.com 等大站的误杀！
    match_suffix = re.match(r'^(\@\@)?\|\|([a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-]+)\^?$', line)
    if match_suffix:
        return match_suffix.group(2), bool(match_suffix.group(1)), False

    match_exact = re.match(r'^(\@\@)?\|([a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-]+)\^?$', line)
    if match_exact:
        return match_exact.group(2), bool(match_exact.group(1)), True

    if line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1]
            if domain not in ['localhost', 'localhost.localdomain', 'local']:
                return domain, False, True

    if '.' in line and ' ' not in line and '/' not in line and '*' not in line and '$' not in line:
        return line, False, True

    return None, None, None

def fetch_content(url):
    print(f"  [拉取中] {url.split('/')[-1]}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  [!] 拉取失败 {url}: {e}")
        return ""

def load_local_list(filepath):
    local_set = set()
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                val = line.strip()
                if val and not val.startswith('#'):
                    if is_valid_domain(val):
                        local_set.add(val)
    return local_set

# ==========================================
# 3. 极速子域名包含去重压缩
# ==========================================
def deduplicate_domains(exact_set, suffix_set):
    print("开始执行跨域子域名去重精简压缩...")
    valid_suffix = set()
    valid_exact = set()
    
    for domain in suffix_set:
        parts = domain.split('.')
        is_subdomain = False
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in suffix_set:
                is_subdomain = True
                break
        if not is_subdomain:
            valid_suffix.add(domain)
            
    for domain in exact_set:
        parts = domain.split('.')
        covered_by_suffix = False
        if domain in valid_suffix:
            covered_by_suffix = True
        else:
            for i in range(1, len(parts) - 1):
                parent = '.'.join(parts[i:])
                if parent in valid_suffix:
                    covered_by_suffix = True
                    break
                    
        if not covered_by_suffix:
            valid_exact.add(domain)
            
    return valid_exact, valid_suffix

# ==========================================
# 4. 主流程控制
# ==========================================
def main():
    raw_domain = set()
    raw_domain_suffix = set()
    upstream_whitelist = set()

    print("=== 步骤 1/4: 高并发拉取并解析基础源 ===")
    all_sources = TXT_SOURCES + AUTHOR_FILES
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_content, all_sources)
        
        for content in results:
            if not content: continue
            for line in content.splitlines():
                domain, is_whitelist, is_exact = parse_adblock_rule(line)
                if domain and is_valid_domain(domain):
                    if is_whitelist:
                        upstream_whitelist.add(domain)
                    elif is_exact:
                        raw_domain.add(domain)
                    else:
                        raw_domain_suffix.add(domain)

    print(f"拉取提取完成。后缀规则: {len(raw_domain_suffix)}，精确规则: {len(raw_domain)}")

    print("=== 步骤 2/4: 读取本地黑白名单 ===")
    local_whitelist = load_local_list("source/noblock.txt")
    local_blocklist = load_local_list("source/block.txt")

    print("=== 步骤 3/4: 级联覆盖与冲突解决 ===")
    raw_domain.difference_update(upstream_whitelist)
    raw_domain_suffix.difference_update(upstream_whitelist)
    
    raw_domain.difference_update(local_whitelist)
    raw_domain_suffix.difference_update(local_whitelist)

    raw_domain_suffix.update(local_blocklist)

    print("=== 步骤 4/4: 核心压缩 ===")
    final_domain, final_domain_suffix = deduplicate_domains(raw_domain, raw_domain_suffix)

    print(f"合并压缩完成！最终后缀拦截: {len(final_domain_suffix)} 条，精确拦截: {len(final_domain)} 条。")

    # ==========================================
    # 5. 生成 JSON
    # ==========================================
    final_rule = {}
    if final_domain:
        final_rule["domain"] = sorted(list(final_domain))
    if final_domain_suffix:
        final_rule["domain_suffix"] = sorted(list(final_domain_suffix))

    output_json = {
        "version": 3,
        "rules": [final_rule] if final_rule else []
    }

    output_path = "source/adg-dns.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_json, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 成功生成 {output_path}，规则已完美纯净！")

if __name__ == "__main__":
    main()

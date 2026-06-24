import urllib.request
import json
import os
import re
import ipaddress
import concurrent.futures # 补齐并发精髓

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

# ==========================================
# 2. 核心解析与校验逻辑
# ==========================================
def is_valid_domain(domain):
    """防核弹校验：排除 IP、非法字符，防止误杀整个顶级域名"""
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    
    # 必须包含字母数字和中划线，且至少包含一个点
    if not re.match(r'^([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+$', domain):
        return False
        
    # 防止拦截顶级域名，如 com, cn, net (长度过短或没有点)
    if '.' not in domain or len(domain) < 4:
        return False
        
    return True

def parse_adblock_rule(line):
    """
    提取纯域名并精准区分类型
    返回格式: (domain, is_whitelist, is_exact)
    """
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#') or line.startswith('['):
        return None, None, None

    # 1. 匹配双竖线后缀拦截 (||example.com^) 或白名单 (@@||example.com^)
    match_suffix = re.match(r'^(\@\@)?\|\|([a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-]+)\^?(?:\$.*)?$', line)
    if match_suffix:
        return match_suffix.group(2), bool(match_suffix.group(1)), False

    # 2. 匹配单竖线精确拦截 (|example.com^) 或白名单 (@@|example.com^) [补齐的精髓]
    match_exact = re.match(r'^(\@\@)?\|([a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-]+)\^?(?:\$.*)?$', line)
    if match_exact:
        return match_exact.group(2), bool(match_exact.group(1)), True

    # 3. 兼容传统 hosts 文件 (精确匹配)
    if line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1]
            if domain not in ['localhost', 'localhost.localdomain', 'local']:
                return domain, False, True # hosts 视为精确拦截

    # 4. 纯文本单行域名 (视为精确匹配)
    if '.' in line and ' ' not in line and '/' not in line and '*' not in line:
        return line, False, True

    return None, None, None

def fetch_content(url):
    print(f"  [线程] 正在拉取: {url.split('/')[-1]}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=10) as response: # 缩短超时，防止死等
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
    """
    不仅在 suffix 内部去重，还会做跨域去重：
    如果 suffix 里有 example.com，那么 exact 里的 www.example.com 也一并删掉
    """
    print("开始执行跨域子域名去重精简压缩...")
    valid_suffix = set()
    valid_exact = set()
    
    # 1. 精简 suffix_set 内部
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
            
    # 2. 精简 exact_set (如果其父域名已被 suffix 拦截，则不需要单独写 exact)
    for domain in exact_set:
        parts = domain.split('.')
        covered_by_suffix = False
        
        # 检查它自己或者它的父级是否在 valid_suffix 中
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
    raw_domain = set()        # 精确拦截
    raw_domain_suffix = set() # 后缀拦截
    upstream_whitelist = set()

    print("=== 步骤 1/4: 高并发拉取并解析基础源 ===")
    all_sources = TXT_SOURCES + AUTHOR_FILES
    
    # 启用线程池并发下载 (补齐的速度精髓)
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

    print(f"拉取完成。原始后缀规则: {len(raw_domain_suffix)}，原始精确规则: {len(raw_domain)}")

    print("=== 步骤 2/4: 读取本地自定义纯净黑白名单 ===")
    local_whitelist = load_local_list("source/noblock.txt")
    local_blocklist = load_local_list("source/block.txt")

    print("=== 步骤 3/4: 执行漏斗级联覆盖与合并 ===")
    # 剔除白名单 (最高优先级)
    raw_domain.difference_update(upstream_whitelist)
    raw_domain_suffix.difference_update(upstream_whitelist)
    
    raw_domain.difference_update(local_whitelist)
    raw_domain_suffix.difference_update(local_whitelist)

    # 补充本地黑名单 (本地的统一作为后缀拦截处理，更彻底)
    raw_domain_suffix.update(local_blocklist)

    print("=== 步骤 4/4: 执行核心压缩算法 ===")
    final_domain, final_domain_suffix = deduplicate_domains(raw_domain, raw_domain_suffix)

    print(f"合并压缩完成！最终后缀拦截: {len(final_domain_suffix)} 条，精确拦截: {len(final_domain)} 条。")

    # ==========================================
    # 5. 生成终极 JSON
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
    
    print(f"✅ 成功生成 {output_path}，已达企业级纯净度！")

if __name__ == "__main__":
    main()

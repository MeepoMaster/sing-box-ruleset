#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
将 ChinaMax_IP.txt (Clash IP 规则列表) 转换为 sing-box JSON 规则集。
输入: ChinaMax_IP.txt
输出: source/cnip.json
"""
import json
import ipaddress
import os

INPUT = "ChinaMax_IP.txt"
OUTPUT_DIR = "source"
OUTPUT = os.path.join(OUTPUT_DIR, "cnip.json")


def normalize(raw):
    """解析一行，返回标准化的 CIDR 字符串；无法识别返回 None。"""
    line = raw.strip()
    if not line or line.startswith("#"):
        return None

    # IPv4 映射的 IPv6 单地址: ::ffff:x.x.x.x/128  ->  x.x.x.x/32
    if line.lower().startswith("::ffff:"):
        rest = line[7:]
        ip_part, sep, prefix = rest.partition("/")
        if sep and prefix == "128":
            try:
                if ipaddress.ip_address(ip_part).version == 4:
                    return f"{ip_part}/32"
            except ValueError:
                pass
        return None

    # 普通 CIDR 校验 + 归一化
    try:
        net = ipaddress.ip_network(line, strict=False)
    except ValueError:
        return None
    return str(net)


def main():
    cidrs = []
    seen = set()
    with open(INPUT, "r", encoding="utf-8") as f:
        for raw in f:
            c = normalize(raw)
            if c and c not in seen:
                seen.add(c)
                cidrs.append(c)

    data = {
        "version": 5,
        "rules": [
            {"ip_cidr": cidrs}
        ],
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote {len(cidrs)} CIDRs to {OUTPUT}")


if __name__ == "__main__":
    main()

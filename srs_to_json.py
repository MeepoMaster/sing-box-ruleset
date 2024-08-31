import json
import struct
import sys

def parse_srs(srs_file_path):
    with open(srs_file_path, 'rb') as f:
        # 读取头部信息
        version = struct.unpack('>I', f.read(4))[0]
        rule_count = struct.unpack('>I', f.read(4))[0]
        
        rules = []
        for _ in range(rule_count):
            rule_type = struct.unpack('B', f.read(1))[0]
            rule_length = struct.unpack('>H', f.read(2))[0]
            rule_content = f.read(rule_length).decode('utf-8')
            
            if rule_type == 0:  # Domain
                rules.append({"type": "domain", "value": rule_content})
            elif rule_type == 1:  # Domain suffix
                rules.append({"type": "domain_suffix", "value": rule_content})
            elif rule_type == 2:  # Domain keyword
                rules.append({"type": "domain_keyword", "value": rule_content})
            elif rule_type == 3:  # Domain regex
                rules.append({"type": "domain_regex", "value": rule_content})
            # 可以根据需要添加更多规则类型

    return {
        "version": version,
        "rules": rules
    }

def srs_to_json(srs_file_path, json_file_path):
    data = parse_srs(srs_file_path)
    with open(json_file_path, 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python srs_to_json.py <input_srs_file> <output_json_file>")
        sys.exit(1)
    
    srs_file_path = sys.argv[1]
    json_file_path = sys.argv[2]
    srs_to_json(srs_file_path, json_file_path)
    print(f"Converted {srs_file_path} to {json_file_path}")

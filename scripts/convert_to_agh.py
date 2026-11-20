import os
import urllib.request

# Источник: список MetaCubeX для Mihomo
SOURCE_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ip-geo-detect.list"
OUTPUT_FILE = "adguard/OwnGeoIPDetectList.txt"


def main():
  req = urllib.request.urlopen(SOURCE_URL, timeout=30)
  lines = req.read().decode("utf-8").splitlines()

  rules = []
  seen = set()

  for raw in lines:
    line = raw.split("#")[0].split("//")[0].strip()
    if not line or " " in line:
      continue

    if line.startswith("+."):
      domain = line[2:].lstrip(".")
      rule = f"||{domain}^"
    elif line.startswith("domain:"):
      domain = line[7:].lstrip(".")
      rule = f"||{domain}^"
    elif line.startswith("."):
      domain = line[1:].lstrip(".")
      rule = f"||*.{domain}^"
    elif line.startswith("full:"):
      domain = line[5:].lstrip(".")
      rule = f"|{domain}^"
    elif ":" in line:
      # Пропускаем keyword: и regexp:, которые не поддерживаются DNS-фильтрами AGH
      continue
    else:
      rule = f"|{line}^"

    if rule not in seen:
      seen.add(rule)
      rules.append(rule)

  header = [
      "! Title: OwnGeoIPDetectList (AdGuard Home)",
      (
          "! Description: Auto-converted IP & Geo detection blocklist for"
          " AdGuard Home"
      ),
      f"! Source: {SOURCE_URL}",
      f"! Total rules: {len(rules)}",
      "!",
  ]

  os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
  with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(header + rules) + "\n")


if __name__ == "__main__":
  main()

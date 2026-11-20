import os
import urllib.request

SOURCE_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ip-geo-detect.list"
OUTPUT_FILE = "adguard/OwnGeoIPDetectList.txt"

EXCLUDED_DOMAINS = {
    "2ip.cc",
    "2ip.ee",
    "2ip.eu",
    "2ip.ge",
    "2ip.info",
    "2ip.io",
    "2ip.kz",
    "2ip.lt",
    "2ip.me",
    "2ip.my",
    "2ip.nl",
    "2ip.ru",
    "2ip.tg",
    "2ip.ua",
    "2ip.uk",
    "browserleaks.com",
    "browserleaks.io",
    "browserleaks.net",
    "browserleaks.org",
}


def is_excluded(domain: str) -> bool:
  return any(
      domain == excluded or domain.endswith("." + excluded)
      for excluded in EXCLUDED_DOMAINS
  )


def main():
  req = urllib.request.urlopen(SOURCE_URL, timeout=30)
  lines = req.read().decode("utf-8").splitlines()

  rules = []
  seen = set()

  for raw in lines:
    line = raw.split("#")[0].split("//")[0].strip().lower()
    if not line or " " in line:
      continue

    if line.startswith("+."):
      domain = line[2:].lstrip(".")
    elif line.startswith("domain:"):
      domain = line[7:].lstrip(".")
    elif line.startswith("full:"):
      domain = line[5:].lstrip(".")
    elif line.startswith("."):
      domain = line[1:].lstrip(".")
    elif ":" in line:
      # Пропускаем keyword: и regexp:, не поддерживаемые в DNS-фильтрах AGH
      continue
    else:
      domain = line.lstrip(".")

    if not domain or is_excluded(domain):
      continue

    rule = f"||{domain}^"
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

import json
import re

with open("gmx.com.har", "r", encoding="utf-8") as f:
    har = json.load(f)

for e in har["log"]["entries"]:
    if e["request"]["url"] == "https://signup.gmx.com/" and e["request"]["method"] == "GET":
        html = e["response"]["content"].get("text", "")
        for pat in ["sk_", "captcha", "ccguid", "statistics", "pulse", "CAPTCHA"]:
            found = re.findall(pat + r"[^\s\"']{0,100}", html[:80000], re.I)
            if found:
                print(pat, found[:8])
        print("html len", len(html))
        break

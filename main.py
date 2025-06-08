import requests
from bs4 import BeautifulSoup
from datetime import datetime
import re
import sqlite3
from urllib.parse import urlparse

# Jina Token 與漏洞 ID
token = "Bearer jina_8fd43733cb3043bba1922514ff91830cPifyRRg7VJa9qGXuFe24Crk-E6D8"
vuln_id = "ZD-2025-00315"
url = f"https://r.jina.ai/https://zeroday.hitcon.org/vulnerability/{vuln_id}"
headers = {
    #"Authorization": token,
    "X-Return-Format": "html"
}

# TANetWhois 查詢函式
def query_tanet_whois(ip):
    try:
        res = requests.get(
            f"https://whois.tanet.edu.tw/showWhoisPublic.php?queryString={ip}",
            headers={"User-Agent": "Mozilla/5.0"}, timeout=10
        )
        res.encoding = "utf-8"
        soup = BeautifulSoup(res.text, "html.parser")
        td_tags = soup.find_all("td")

        institution = None
        domain = None

        for i, td in enumerate(td_tags):
            if "用戶單位網段" in td.get_text(strip=True):
                if i + 2 < len(td_tags):
                    institution = td_tags[i + 2].get_text(strip=True)
                if i + 10 < len(td_tags):
                    domain_candidate = td_tags[i + 10].get_text(strip=True)
                    domain_match = re.search(r"@([\w\.-]+)", domain_candidate)
                    if domain_match:
                        domain_str = domain_match.group(1)
                        if domain_str.endswith("edu.tw"):
                            domain = domain_str
                break
        return institution, domain
    except Exception:
        return None, None

# 連接資料庫
db_path = r"C:/Users/jay00/OneDrive/桌面/zeroday/zzd.sqlite"
conn = sqlite3.connect(db_path)
cur = conn.cursor()

severity_map = {"無": 1, "低": 2, "中": 3, "高": 4, "嚴重": 5}

# 取得並解析 Jina HTML
res = requests.get(url, headers=headers, timeout=40)
soup = BeautifulSoup(res.text, "html.parser")

# 基本欄位擷取
zdid = soup.select_one("span.value")
vendor = soup.select_one("span.value.tx-overflow-ellipsis")
severity_raw = soup.find("li", string=re.compile("風險："))
vuln_name_raw = soup.find("li", string=re.compile("類型："))
log_dates = [tag.get_text(strip=True).replace("/", "-") for tag in soup.select(".log-date")]

zdid = zdid.text.strip() if zdid else None
vendor = vendor.text.strip() if vendor else None
severity = severity_raw.get_text(strip=True).split("：")[1] if severity_raw else None
severity_sn = severity_map.get(severity)
vuln_name = vuln_name_raw.get_text(strip=True).split("：")[1] if vuln_name_raw else None

when_start = when_ended = None
if log_dates:
    parsed_dates = sorted([datetime.strptime(d, "%Y-%m-%d %H:%M:%S") for d in log_dates])
    when_start = parsed_dates[0].strftime("%Y-%m-%d %H:%M:%S")
    when_ended = parsed_dates[-1].strftime("%Y-%m-%d %H:%M:%S") if len(parsed_dates) > 1 else when_start

# 漏洞說明
vuln_desc = None
ref = soup.find("h3", string="參考資料")
if ref:
    for sib in ref.find_next_siblings():
        if sib.name == "h3":
            break
        text = sib.get_text(strip=True)
        if text:
            vuln_desc = text
            break

if not vuln_desc:
    desc = soup.find("h3", string="敘述")
    if desc:
        for sib in desc.find_next_siblings():
            if sib.name == "h3":
                break
            text = sib.get_text(strip=True)
            if text:
                vuln_desc = text
                break

if not vuln_desc:
    vuln_desc = "（無資料）"

# 寫入 vulnerability
vuln_sn = None
if vuln_name and vuln_desc:
    cur.execute("SELECT sn FROM vulnerability WHERE name = ?", (vuln_name,))
    row = cur.fetchone()
    if row:
        vuln_sn = row[0]
    else:
        cur.execute("INSERT INTO vulnerability (name, description) VALUES (?, ?)", (vuln_name, vuln_desc))
        vuln_sn = cur.lastrowid

# 寫入 incident
incident_sn = None
if zdid and vendor and severity_sn and vuln_sn and when_start:
    cur.execute("""
        INSERT OR IGNORE INTO incident (id, vendor, severity_sn, vulnerability_sn, when_start, when_ended)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (zdid, vendor, severity_sn, vuln_sn, when_start, when_ended))
    conn.commit()
    cur.execute("SELECT sn FROM incident WHERE id = ?", (zdid,))
    incident_sn = cur.fetchone()[0]
    print(f"{zdid} 寫入 incident 完成")
else:
    print("資料不完整")

# 處理 target hostname
urls_block = soup.select_one("div.urls")
if urls_block and incident_sn:
    urls = re.findall(r"https?://[^\s<]+", urls_block.decode_contents())
    hostnames = []
    if urls:
        first_hostname = urlparse(urls[0]).hostname
        if first_hostname:
            hostnames = [first_hostname]  # 只處理第一個 hostname

    for hostname in hostnames:
        institution_sn = None
        category_sn = 7
        name_override = None
        whois_domain = None

        # 若是 IP
        if re.match(r"\d+\.\d+\.\d+\.\d+", hostname):
            inst_name, whois_domain = query_tanet_whois(hostname)
            if whois_domain and whois_domain.endswith("edu.tw"):
                cur.execute("SELECT sn, domain_name FROM institution WHERE domain_name IS NOT NULL")
                for sn, dom in cur.fetchall():
                    if whois_domain.endswith(dom):
                        institution_sn = sn
                        break
                else:
                    name_override = inst_name

                cur.execute("SELECT sn, domain_name FROM category WHERE domain_name IS NOT NULL")
                for sn, dom in cur.fetchall():
                    if dom in whois_domain:
                        category_sn = sn
                        break
        else:
            # 若是 domain
            cur.execute("SELECT sn, domain_name FROM institution WHERE domain_name IS NOT NULL")
            for sn, dom in cur.fetchall():
                if hostname.endswith(dom):
                    institution_sn = sn
                    break
            cur.execute("SELECT sn, domain_name FROM category WHERE domain_name IS NOT NULL")
            for sn, dom in cur.fetchall():
                if dom in hostname:
                    category_sn = sn
                    break

        # 寫入 target
        cur.execute("SELECT 1 FROM target WHERE hostname = ? AND incident_sn = ?", (hostname, incident_sn))
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO target (hostname, category_sn, incident_sn, institution_sn, name)
                VALUES (?, ?, ?, ?, ?)
            """, (hostname, category_sn, incident_sn, institution_sn, name_override))
            conn.commit()
            print(f"寫入 target：{hostname}")
else:
    print("無 target 或 incident_sn")

conn.close()
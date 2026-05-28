from neo4j import GraphDatabase
import ollama
import os
import re

from vector_store import load_vector_db, retrieve

URI = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
PASSWORD = os.getenv("NEO4J_PASSWORD", "12345678")

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
VECTOR_INDEX, VECTOR_TEXTS = load_vector_db()


def detect_intent(query):
    q = query.lower()

    if any(x in q for x in [
        "tell me something random",
        "random fact",
        "joke",
        "weather",
        "movie",
        "song",
        "universe",
        "space",
        "sports",
        "food",
        "recipe",
        "history",
        "capital of",
        "homework",
    ]):
        return "OUT_OF_SCOPE_HELP"

    if is_unclear_input(q):
        return "UNCLEAR_HELP"

    if re.search(r"\bwhy\s+is\s+srv-\d+\s+risky\b", q):
        return "ASSET_DRILLDOWN"

    if re.search(r"\bexplain\s+risk\s+(in|for|of)\s+srv-\d+\b", q):
        return "ASSET_DRILLDOWN"

    if re.search(r"\bexplain\s+srv-\d+\b", q):
        return "ASSET_DRILLDOWN"

    if any(x in q for x in ["why is this system vulnerable", "why is my system vulnerable", "why is system vulnerable"]):
        return "VAGUE_SYSTEM_VULNERABLE_HELP"

    if re.search(r"\bwhat\s+is\s+wrong\s+with\s+srv-\d+\b", q):
        return "ASSET_DRILLDOWN"

    if re.search(r"\bmore\s+risky\s+srv-\d+\s+or\s+srv-\d+\b", q) or re.search(r"\bsrv-\d+\s+or\s+srv-\d+\b", q):
        return "COMPARE_ASSETS_HELP"

    if any(x in q for x in ["compare two systems", "compare systems", "compare two assets", "compare assets"]):
        return "COMPARE_ASSETS_MISSING_IDS_HELP"

    personal_device_words = ["mobile", "phone", "laptop", "desktop", "pc", "computer", "device", "system"]
    personal_issue_words = ["issue", "problem", "not working", "slow", "hanging", "crash", "error"]
    if any(x in q for x in personal_device_words) and any(x in q for x in personal_issue_words):
        return "EMPLOYEE_DEVICE_HELP"

    if any(x in q for x in [
        "safe from phishing",
        "safe from phishing attacks",
        "am i safe from phishing",
        "is my system safe from phishing",
        "how to stay safe from phishing",
        "avoid phishing",
        "protect from phishing",
        "prevent phishing",
    ]):
        return "PHISHING_EDUCATION_HELP"

    if any(x in q for x in ["what happens if system is attacked", "what happens if a system is attacked", "what if system is attacked", "what happens during an attack"]):
        return "ATTACK_IMPACT_EDUCATION_HELP"

    if re.search(r"\b(top\s+\d+|top\s+five|top\s+ten|list|show)\s+attacks?\b", q) or (
        "attack" in q and any(x in q for x in ["dangerous", "most dangerous", "top 5", "top five"])
    ):
        return "MOST_LIKELY_ATTACK_HELP"

    if "phishing" in q or "phising" in q:
        return "PHISHING_HELP"

    if any(x in q for x in ["why is malware dangerous", "what is malware", "explain malware"]):
        return "MALWARE_EDUCATION_HELP"

    if "ransomware" in q and any(x in q for x in ["systems", "assets", "list", "which"]):
        return "RANSOMWARE_SYSTEMS_HELP"

    if "malware" in q or "virus" in q or "ransomware" in q:
        return "MALWARE_HELP"

    if "ddos" in q or "denial of service" in q or " dos" in f" {q}" or "unavailable" in q or "availability" in q:
        return "DOS_HELP"

    if "sql injection" in q or "sqli" in q:
        return "SQL_INJECTION_HELP"

    if any(x in q for x in ["top 10", "top ten", "10 risk", "ten risk"]):
        return "TOP_10_RISKS_HELP"

    if any(x in q for x in ["is my system safe", "am i safe", "is our system safe", "are we safe"]):
        return "SYSTEM_SAFETY_HELP"

    if any(x in q for x in [
        "something wrong with my system",
        "anything wrong with my system",
        "is something wrong",
        "is anything wrong",
        "system acting strange",
        "system looks strange",
        "should i be worried",
        "should we be worried",
        "do i need to worry",
        "do we need to worry",
        "am i in danger",
    ]):
        return "SYSTEM_CONCERN_HELP"

    if any(x in q for x in ["risk in my server", "server risk", "risk on my server", "is my server risky", "risk in server"]):
        return "SERVER_RISK_HELP"

    if re.search(r"\b(list|show|give|display)\s+(top\s+5|top five|five|5)\b", q) and any(
        x in q for x in ["vulnerable", "risky", "risk", "unsafe"]
    ):
        return "MOST_VULNERABLE_SYSTEMS_HELP"

    if any(x in q for x in [
        "which systems are most vulnerable",
        "most vulnerable systems",
        "most vulnerable assets",
        "top vulnerable systems",
        "top vulnerable assets",
        "vulnerable systems",
        "vulnerable assets",
        "top risky assets",
        "top risky systems",
        "show top risky assets",
        "show top risky systems",
        "risky assets",
        "risky systems",
        "unsafe systems",
        "unsafe assets",
        "list unsafe systems",
        "list unsafe assets",
    ]):
        return "MOST_VULNERABLE_SYSTEMS_HELP"

    if any(x in q for x in ["highest issues", "most issues", "highest issue", "most issue"]):
        return "HIGHEST_ISSUES_HELP"

    if any(x in q for x in ["which system is safer", "which system is safest", "safest system", "safer system", "least risky system"]):
        return "SAFEST_SYSTEM_HELP"

    if any(x in q for x in ["attack exposure", "show attack exposure", "exposed to attack", "attack exposed"]):
        return "ATTACK_EXPOSURE_HELP"

    if (
        re.search(r"\b(to\s+which|which|what)\s+attack\b", q)
        and any(x in q for x in ["most vulnerable", "vulnerable", "exposed", "risk"])
    ):
        return "MOST_LIKELY_ATTACK_HELP"

    if any(x in q for x in [
        "which software is causing most risk",
        "software causing most risk",
        "riskiest software",
        "most risky software",
        "which software has most risk",
        "software has highest risk",
    ]):
        return "SOFTWARE_RISK_HELP"

    if re.search(r"\bis\s+[a-z0-9 ._-]+\s+causing\s+(issues|risk|problems)\b", q):
        return "SPECIFIC_SOFTWARE_RISK_HELP"

    if any(x in q for x in [
        "which system has risky software",
        "which systems have risky software",
        "which asset use vulnerable software",
        "which assets use vulnerable software",
        "assets use vulnerable software",
        "asset use vulnerable software",
        "assets with vulnerable software",
        "systems with vulnerable software",
        "systems with risky software",
        "system with risky software",
        "risky software systems",
    ]):
        return "RISKY_SOFTWARE_SYSTEMS_HELP"

    if any(x in q for x in [
        "most vulnerable",
        "top risk",
        "highest risk",
        "most risky",
        "worry about the most",
        "worried about the most",
        "most worried about",
        "biggest risk",
        "largest risk",
        "main risk",
        "highest concern",
        "at most risk",
        "most at risk",
        "asset at most risk",
    ]):
        return "MOST_VULNERABLE_HELP"

    if any(x in q for x in ["which vulnerability", "what vulnerability", "most exposed", "most exposure"]):
        return "MOST_EXPOSED_VULN_HELP"

    attack_status_words = [
        "under attack",
        "being attacked",
        "am i attacked",
        "are we attacked",
        "am i hacked",
        "is my system hacked",
        "is our system hacked",
        "has my system been hacked",
        "has our system been hacked",
        "is my system compromised",
        "is our system compromised",
        "active attack",
        "ongoing attack",
        "is my system under attack",
        "is our system under attack",
    ]
    if any(x in q for x in attack_status_words):
        return "ATTACK_STATUS"

    if any(x in q for x in ["most vulnerable", "top risk", "highest risk", "issue", "problem", "status", "check"]):
        return "TOP_ASSETS"

    if any(x in q for x in ["spread", "connected", "network", "subnet", "attack exposure", "exposure"]):
        return "ATTACK_SURFACE"

    if any(x in q for x in ["attack", "phishing", "malware", "virus", "ransomware", "dos", "denial"]):
        return "ATTACK_QUERY"

    return "GENERAL_RISK"


def direct_employee_answer(intent, query):
    if intent == "UNCLEAR_HELP":
        return """Short answer:
I could not understand the question, so I cannot check a system or risk from it.

Affected system:
No company system is confirmed from this question.

Why it matters:
The assistant should only use the security graph when the question clearly mentions a system, software, vulnerability, attack type, or risk.

What to do:
Ask a clear cyber-safety question, such as: which systems are most vulnerable? is MySQL causing issues? or why is SRV-032 risky?

Evidence used:
No graph data was used because the question was unclear.
"""

    if intent == "OUT_OF_SCOPE_HELP":
        return """Short answer:
I am built to answer company cyber-safety questions, not general random questions.

Affected system:
No company system is involved in this question.

Why it matters:
Keeping the assistant focused helps avoid giving unrelated or misleading security answers.

What to do:
Ask about a system, software, vulnerability, attack type, or risk. For example: which systems are most vulnerable? or is MySQL causing issues?

Evidence used:
No graph data was used because the question was outside the cyber-safety scope.
"""

    if intent == "COMPARE_ASSETS_MISSING_IDS_HELP":
        return """Short answer:
I need two asset IDs before I can compare systems. I should not guess which systems you mean.

Affected system:
No specific systems are confirmed yet.

Why it matters:
A fair comparison needs records for both systems, such as known software risk records, highest severity score, business criticality, subnet, and connected systems.

What to do:
Ask again with two asset IDs, for example: which is more risky SRV-032 or SRV-049?

Evidence used:
No graph comparison was run because the two asset IDs were not provided.
"""

    if intent == "COMPARE_ASSETS_HELP":
        asset_ids = extract_asset_ids(query)
        data = execute_query(compare_assets_query(), {"asset_ids": asset_ids})
        by_id = {row.get("asset_id"): row for row in data}
        missing = [asset for asset in asset_ids if asset not in by_id]

        if len(data) >= 2:
            ranked = sorted(data, key=lambda row: row.get("risk_score") or 0, reverse=True)
            top = ranked[0]
            lines = []
            for row in ranked:
                software = ", ".join(row.get("software") or ["unknown software"])
                lines.append(
                    f"{row.get('asset_id')} ({row.get('hostname')}) - score {row.get('risk_score')}, "
                    f"{row.get('known_issues')} known software risk records, highest severity {row.get('highest_score')}, "
                    f"{row.get('connected_systems')} connected systems, {row.get('criticality', 'Unknown')} business criticality. "
                    f"Software: {software}."
                )

            comparison = "\n".join(lines)
            return f"""Short answer:
{top.get('asset_id')} is more risky in the current data. This is a risk comparison, not proof that either system is under attack.

Comparison:
{comparison}

Why it matters:
The ranking uses known software risk records, highest severity score, business criticality, subnet, and connected systems. A higher score means IT should review that asset first.

What to do:
Use trusted company apps and links only. Report unusual errors, pop-ups, slow behavior, or unexpected login requests to IT helpdesk. Ask IT to prioritize patching and configuration review for the higher-risk asset first.

Evidence used:
Asset inventory, software list, vulnerability records, business criticality, and network context.
"""

        return f"""Short answer:
I could not compare those assets because not all asset IDs were found in the current graph data.

Affected system:
Missing asset records: {', '.join(missing) if missing else 'not enough matching asset data'}.

Why it matters:
The assistant needs records for both assets before it can compare risk.

What to do:
Ask IT to confirm that both assets are included in the asset inventory and vulnerability data.

Evidence used:
Current graph data only.
"""

    if intent == "SPECIFIC_SOFTWARE_RISK_HELP":
        software_name = extract_software_name(query)
        data = execute_query(specific_software_risk_query(), {"software": normalize_query_name(software_name)})
        if data:
            row = data[0]
            assets = ", ".join(row.get("example_assets") or ["no asset listed"])
            cves = ", ".join(row.get("example_cves") or ["no CVE listed"])
            return f"""Short answer:
Yes, {software_name} has known software risk records in the current data. This does not prove an active attack; it means IT should review where {software_name} is installed.

Affected systems:
{software_name} appears on {row.get('asset_count')} assets. Example affected assets: {assets}.

Why it matters:
The current graph links {software_name} to {row.get('known_issues')} known software risk records, with the highest severity score listed as {row.get('highest_score')}. These records mean updates or safer settings may be needed.

What to do:
Employees should use trusted company apps and links only, and report unusual errors, slow behavior, pop-ups, or unexpected login requests to IT helpdesk. IT should prioritize patching and configuration review for {software_name} on the affected assets.

Evidence used:
Software inventory, asset inventory, and vulnerability records. Example records: {cves}.
"""

        return f"""Short answer:
I did not find known software risk records for {software_name} in the current graph data.

Affected systems:
No affected systems are confirmed for {software_name}.

Why it matters:
This may mean {software_name} is not installed in the current asset inventory, or it has no linked vulnerability records in the graph.

What to do:
Ask IT to confirm the software name and whether the latest asset and vulnerability data are loaded.

Evidence used:
Current software inventory and vulnerability graph data.
"""

    if intent == "MALWARE_EDUCATION_HELP":
        return """Short answer:
Malware is dangerous because it can make a device or business system behave in harmful ways. This answer is general education, not proof that malware is present in your company systems.

Affected system:
No specific affected system is confirmed from this question.

Why it matters:
Malware can slow devices, damage files, steal information, show fake login pages, or stop people from using important systems. It often arrives through unexpected links, attachments, downloads, or fake update prompts.

What to do:
Do not open unexpected attachments, downloads, or links. Do not enter passwords into pop-ups or pages opened from suspicious messages. Report unusual pop-ups, unknown apps, repeated login prompts, or very slow behavior to IT helpdesk.

Evidence used:
No graph data was needed because this was a general malware explanation.
"""

    if intent == "PHISHING_EDUCATION_HELP":
        return """Short answer:
To stay safe from phishing, be careful with unexpected messages, links, attachments, and login pages. This is general safety guidance, not proof that a phishing attack is happening right now.

Affected system:
No specific affected system is confirmed from this question.

Why it matters:
Phishing tries to trick people into sharing passwords, opening harmful files, approving fake requests, or visiting fake login pages.

What to do:
Do not enter passwords after clicking a message link. Check the sender and website address carefully. Report suspicious messages to IT helpdesk instead of replying or forwarding them widely.

Evidence used:
No graph data was needed because this was a general phishing-safety question.
"""

    if intent == "ATTACK_IMPACT_EDUCATION_HELP":
        return """Short answer:
If a system is attacked, it may become slow, unavailable, show unusual behavior, or expose business data. This is a general explanation, not proof that an attack is happening right now.

Affected system:
No specific affected system is confirmed from this question.

Why it matters:
An attack can interrupt work, block access to important services, change or damage files, or trick employees into sharing passwords. The exact impact depends on the type of attack and which system is affected.

What to do:
Report unusual pop-ups, unknown apps, repeated login prompts, missing files, very slow systems, or unavailable services to IT helpdesk. Do not try to diagnose it yourself, and do not open unknown links or attachments.

Evidence used:
No graph data was needed because this was a general cyber-safety question.
"""

    if intent == "VAGUE_SYSTEM_VULNERABLE_HELP":
        data = execute_query(build_query("TOP_ASSETS"))
        if data:
            row = data[0]
            software = ", ".join(row.get("software") or ["unknown software"])
            cves = ", ".join(row.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
I do not know which exact system you mean by "this system", so I am using the highest-priority system in the current data: {row.get('asset_id')}. It is vulnerable because it has known software risk records that IT should review.

Affected system:
{row.get('asset_id')} ({row.get('hostname')}) in the {row.get('department', 'Unknown')} department, subnet {row.get('subnet', 'Unknown')}, running {software}.

Why it matters:
This system has {row.get('known_issues')} known software risk records and the highest severity score is {row.get('highest_score')}. These records mean updates or safer settings may be needed, but they do not prove the system is under attack.

What to do:
Use trusted company apps and links only. Report unusual errors, pop-ups, slow behavior, or unexpected login requests to IT helpdesk. Ask IT to prioritize patching and configuration review for {row.get('asset_id')}.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
I do not know which exact system you mean, and no vulnerable system was found in the current graph data.

Affected system:
No single affected system is confirmed.

Why it matters:
The assistant needs an asset ID, such as SRV-032, to explain one specific system.

What to do:
Ask again with the asset ID if you know it, for example: why is SRV-032 risky?

Evidence used:
Current graph data only.
"""

    if intent == "ASSET_ISSUE_EXPLANATION_HELP":
        asset_id = extract_asset_id(query)
        data = execute_query(asset_risk_explanation_query(), {"asset_id": asset_id})
        if data:
            row = data[0]
            software = ", ".join(row.get("software") or ["unknown software"])
            cves = ", ".join(row.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
The current data does not prove that {asset_id} is broken or under attack. It shows known software risk records that IT should review.

Affected system:
{asset_id} ({row.get('hostname')}) in the {row.get('department', 'Unknown')} department, subnet {row.get('subnet', 'Unknown')}, running {software}.

Why it matters:
{asset_id} has {row.get('known_issues')} known software risk records, the highest severity score is {row.get('highest_score')}, and it is connected to {row.get('connected_systems')} other systems. These are review signals, not proof of a current problem.

What to do:
If you see unusual errors, pop-ups, slow behavior, unknown apps, or unexpected login requests, report them to IT helpdesk with the time and details. Do not open unknown links or attachments. Ask IT to review updates and settings for {asset_id}.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return f"""Short answer:
I could not find {asset_id} in the current graph data, so I cannot say what is wrong with it.

Affected system:
No matching asset is confirmed.

Why it matters:
The assistant needs asset, software, and vulnerability records before it can explain a specific system.

What to do:
Ask IT to confirm that {asset_id} is included in the asset inventory and vulnerability data.

Evidence used:
Current graph data only.
"""

    if intent == "ASSET_RISK_EXPLANATION_HELP":
        asset_id = extract_asset_id(query)
        data = execute_query(asset_risk_explanation_query(), {"asset_id": asset_id})
        if data:
            row = data[0]
            software = ", ".join(row.get("software") or ["unknown software"])
            cves = ", ".join(row.get("example_cves") or ["no example CVE listed"])
            reason = asset_risk_reason(row)
            return f"""Short answer:
{asset_id} is risky because {reason}. This does not prove the system is under attack.

Affected system:
{asset_id} ({row.get('hostname')}) in the {row.get('department', 'Unknown')} department, subnet {row.get('subnet', 'Unknown')}, running {software}.

Why it matters:
The system has {row.get('known_issues')} known software risk records, the highest severity score is {row.get('highest_score')}, and it is connected to {row.get('connected_systems')} other systems. These factors mean IT should review updates and settings before the risk becomes a business problem.

What to do:
Use trusted company apps and links only. Report unusual errors, pop-ups, slow behavior, or unexpected login requests to IT helpdesk. Ask IT to prioritize patching and configuration review for {asset_id}.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, business criticality, and network context. Example records: {cves}.
"""

        return f"""Short answer:
I could not find {asset_id} in the current graph data.

Affected system:
No matching asset is confirmed.

Why it matters:
The system needs asset, software, and vulnerability records before it can explain risk for a specific asset.

What to do:
Ask IT to confirm that {asset_id} is included in the asset inventory and vulnerability data.

Evidence used:
Current graph data only.
"""

    if intent == "ATTACK_STATUS":
        return """Short answer:
I cannot see clear evidence of an active attack from the current asset and vulnerability data. The system can show known weaknesses and risky systems, but it does not prove that an attack is happening right now.

Affected system:
No single attacked system is confirmed from this question.

Why it matters:
Known vulnerabilities mean some systems may need updates or safer settings, but a vulnerability is not the same as an active attack.

What to do:
If something looks unusual, report it to IT helpdesk with what you saw and when it happened. Do not open unknown links or files. Continue using normal company channels instead of trying to diagnose it yourself.

Evidence used:
This answer is based on asset inventory, software vulnerability records, weakness records, and network context; no live attack signal was provided.
"""

    if intent == "MOST_LIKELY_ATTACK_HELP":
        data = execute_query(most_likely_attack_query(5))
        if not data:
            return """Short answer:
The current graph does not have enough attack-mapping data to identify which attack type is most relevant.

Affected system:
No specific affected system is confirmed from this question.

Why it matters:
The assistant should only answer from mapped asset, vulnerability, weakness, and attack data.

What to do:
Ask about a known risk type such as phishing, malware, ransomware, SQL injection, or denial of service.

Evidence used:
Current attack mapping and graph data only.
"""

        top = data[0]
        lines = []
        for i, row in enumerate(data, start=1):
            assets = ", ".join(row.get("example_assets") or ["no example asset listed"])
            lines.append(
                f"{i}. {row.get('attack_type')} - linked to {row.get('known_issues')} software risk records "
                f"across {row.get('asset_count')} assets. Example assets: {assets}."
            )
        attack_list = "\n".join(lines)
        return f"""Short answer:
The strongest mapped attack-related risk is {top.get('attack_type')}. This is based on known weakness-to-attack links, not proof that this attack is happening right now.

Affected system:
No single personal system is confirmed. Example higher-risk assets include {", ".join(top.get("example_assets") or ["no example asset listed"])}.

Attack types found:
{attack_list}

Why it matters:
These attack types are linked to known software risk records in the graph. There is no clear sign of an ongoing attack right now.

What to do:
Use trusted company apps and links only. Report unusual pop-ups, login requests, slow systems, or suspicious messages to IT helpdesk.

Evidence used:
Asset inventory, vulnerability records, weakness records, and mapped attack categories.
"""

    if intent == "EMPLOYEE_DEVICE_HELP":
        return """Short answer:
Your system issue is not enough by itself to say the company is under cyber attack. It may be a normal device problem, app issue, network issue, or update problem.

Affected system:
Your work device or system is the affected item, not a confirmed company server.

Why it matters:
Some device problems are harmless, but unusual pop-ups, unknown apps, repeated login prompts, or unexpected payment/password requests should be treated carefully.

What to do:
Restart the device and update the app/system if safe to do so. Do not enter passwords into suspicious pop-ups or links. Report the issue to IT helpdesk with the device name, screenshots if available, and when the issue started.

Evidence used:
This answer uses only your description; no company asset or attack evidence was confirmed.
"""

    if intent == "PHISHING_HELP":
        data = execute_query(build_query("ATTACK_QUERY"), {"attack_list": ["Phishing"]})
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
The data does not prove that a phishing attack is happening right now. It shows that {top.get('asset_id')} has records connected to phishing-related weakness patterns, so IT should review it as a priority.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
Phishing usually targets people through messages, links, or fake login pages. A risky system can make the impact worse if an employee is tricked into sharing a password or opening a harmful link.

What to do:
Do not open unexpected links or attachments. Do not enter passwords after clicking a message link. Report suspicious messages to IT helpdesk and ask IT to review the listed system and software updates.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
The current data does not show a specific company asset connected to phishing-related risk.

Affected system:
No single affected asset is confirmed.

Why it matters:
Phishing usually targets employees through fake messages, links, attachments, or login pages.

What to do:
Do not open unexpected links or attachments. Do not enter passwords after clicking a message link. Report suspicious messages to IT helpdesk.

Evidence used:
This answer uses the current asset and vulnerability graph, but no matching phishing-related asset was found.
"""

    if intent == "MALWARE_HELP":
        data = execute_query(malware_risk_query())
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
{top.get('asset_id')} has the strongest malware-related risk in the current data. This does not prove malware is installed or that an attack is happening right now.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
Malware risk usually increases when a system has serious software weaknesses, risky exposure, or software that needs patching. If an employee opens a harmful file or link, an already weak system can be easier to misuse.

What to do:
Do not open unexpected attachments, downloads, or links. Report unusual pop-ups, slow behavior, unknown apps, or repeated login prompts to IT helpdesk. Ask IT to prioritize updates and configuration review for {top.get('asset_id')}.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
No specific asset with malware-related risk was found in the current graph data.

Affected system:
No single affected asset is confirmed.

Why it matters:
Malware usually reaches employees through harmful links, attachments, downloads, or fake update prompts.

What to do:
Do not open unexpected attachments, downloads, or links. Report suspicious messages, unknown apps, or unusual pop-ups to IT helpdesk.

Evidence used:
This answer uses the current asset and vulnerability graph, but no matching malware-related asset was found.
"""

    if intent == "RANSOMWARE_SYSTEMS_HELP":
        data = execute_query(ransomware_systems_query(5))
        if not data:
            return """Short answer:
No specific systems with ransomware-related risk were found in the current graph data.

Affected systems:
No single affected system is confirmed.

Why it matters:
Ransomware usually spreads through harmful links, attachments, downloads, weak access, or unpatched software.

What to do:
Do not open unexpected attachments, downloads, or links. Report suspicious messages, unknown apps, unusual pop-ups, or repeated login prompts to IT helpdesk.

Evidence used:
This answer uses the current asset and vulnerability graph, but no matching ransomware-related systems were found.
"""

        lines = []
        for i, row in enumerate(data, start=1):
            software = ", ".join(row.get("software") or ["unknown software"])
            lines.append(
                f"{i}. {row.get('asset_id')} ({row.get('hostname')}) - "
                f"{row.get('department', 'Unknown')} department, {row.get('subnet', 'Unknown')} subnet, "
                f"{row.get('known_issues')} ransomware-related risk records, highest score {row.get('highest_score')}. "
                f"Software: {software}."
            )

        ranked_list = "\n".join(lines)
        return f"""Short answer:
These systems have the strongest ransomware-related risk in the current data. This does not prove ransomware is present or that an attack is happening right now.

Systems to review:
{ranked_list}

Why it matters:
Ransomware can make files or systems unavailable. Risk is higher when important systems have serious software weaknesses or exposure that IT has not fixed yet.

What to do:
Do not open unexpected attachments, downloads, or links. Report unusual pop-ups, unknown apps, slow systems, or repeated login prompts to IT helpdesk. IT should prioritize patching and configuration review for the listed systems.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context.
"""

    if intent == "DOS_HELP":
        wants_list = any(x in query.lower() for x in ["which assets", "which systems", "assets", "systems", "list", "top"])
        data = execute_query(dos_risk_query(5 if wants_list else 1))
        if data:
            if wants_list:
                lines = []
                for i, row in enumerate(data, start=1):
                    software = ", ".join(row.get("software") or ["unknown software"])
                    lines.append(
                        f"{i}. {row.get('asset_id')} ({row.get('hostname')}) - "
                        f"{row.get('department', 'Unknown')} department, {row.get('subnet', 'Unknown')} subnet, "
                        f"{row.get('known_issues')} denial-of-service-related risk records, highest score {row.get('highest_score')}. "
                        f"Software: {software}."
                    )
                asset_list = "\n".join(lines)
                return f"""Short answer:
These assets have the strongest denial-of-service-related risk in the current graph. This does not prove a DDoS attack is happening right now.

Assets to review:
{asset_list}

Why it matters:
Denial of service means a system may become slow or unavailable. Reviewing the highest-ranked assets first can reduce the chance of business disruption.

What to do:
If a service is slow or unavailable, report it to IT helpdesk with the time and what you were trying to access. IT should prioritize patching and configuration review for the listed assets.

Evidence used:
Asset inventory, vulnerability records, weakness records, and network context.
"""

            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
{top.get('asset_id')} has the strongest denial-of-service-related risk in the current data. This does not prove a denial-of-service attack is happening right now.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
Denial of service means a system may become slow or unavailable. If this asset is affected, employees may be unable to use a business service until IT fixes the cause.

What to do:
If a service is slow or unavailable, report it to IT helpdesk with the time and what you were trying to access. Do not repeatedly refresh or retry large actions. Ask IT to prioritize patching and configuration review for {top.get('asset_id')}.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
No specific asset with denial-of-service-related risk was found in the current graph data.

Affected system:
No single affected asset is confirmed.

Why it matters:
Denial of service usually means a business system becomes slow or unavailable.

What to do:
If a service is slow or unavailable, report it to IT helpdesk with the time and what you were trying to access.

Evidence used:
This answer uses the current asset and vulnerability graph, but no matching denial-of-service-related asset was found.
"""

    if intent == "SQL_INJECTION_HELP":
        data = execute_query(sql_injection_query())
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
{top.get('asset_id')} is the asset that needs the most attention for SQL-injection-related risk. This does not mean an attack is happening right now; it means the system has known records that IT should review first.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
SQL injection is a weakness in an application or database-facing service. If it is not fixed, someone could misuse a form, page, or request to access or change data.

What to do:
Use only trusted company apps and links. Do not enter company data into suspicious pages. Ask IT helpdesk to update the listed software and review the affected application or database service.

Evidence used:
Asset inventory, software list, vulnerability records, CWE weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
No specific asset with SQL-injection-related risk was found in the current graph data.

Affected system:
No single affected asset is confirmed.

Why it matters:
SQL injection usually affects applications or database-facing services, not normal employee behavior directly.

What to do:
Use trusted company apps only. Do not enter company data into suspicious pages. Report strange forms or login pages to IT helpdesk.

Evidence used:
This answer uses the current asset and vulnerability graph, but no matching SQL-injection-related asset was found.
"""

    if intent == "MOST_VULNERABLE_HELP":
        data = execute_query(build_query("TOP_ASSETS"))
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            highest_score = top.get("highest_score", "unknown")
            known_issues = top.get("known_issues", "unknown")
            return f"""Short answer:
{top.get('asset_id')} is the asset that needs the most attention right now. This means it has the highest number or severity of known software risk records in the current data, not that it is confirmed to be under attack.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
This system has {known_issues} known software risk records, with the highest severity score listed as {highest_score}. If these records are not reviewed, the system may need updates or safer settings.

What to do:
Use normal company apps and links only. Report unusual errors, pop-ups, login requests, or suspicious messages to IT helpdesk. Ask IT to prioritize updates and configuration review for this asset.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
No vulnerable asset was found in the current graph data.

Affected system:
No single affected asset is confirmed.

Why it matters:
The system needs asset and vulnerability records before it can rank risk.

What to do:
Ask IT to confirm that the asset inventory and vulnerability data are loaded.

Evidence used:
This answer uses the current graph data, but no matching asset risk records were found.
"""

    if intent == "MOST_EXPOSED_VULN_HELP":
        data = execute_query(most_exposed_vulnerability_query())
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            weakness = top.get("weakness_name") or top.get("weakness_id") or "a known software weakness"
            description = top.get("description") or "No description is available in the current data."
            short_description = description[:260].rsplit(" ", 1)[0]
            if len(description) > len(short_description):
                short_description += "..."

            return f"""Short answer:
The system is most exposed to {top.get('cve_id')} based on the current vulnerability data. This does not mean an attack is happening right now; it means this item should be reviewed first.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
The vulnerability has severity score {top.get('cvss', 'unknown')} and is linked to {weakness}. In simple terms: {short_description}

What to do:
Use only trusted company apps and links. Report unusual errors, pop-ups, or login requests to IT helpdesk. Ask IT to prioritize patching or configuration review for {top.get('asset_id')} and {top.get('cve_id')}.

Evidence used:
Asset inventory, software list, vulnerability record {top.get('cve_id')}, weakness records, and network context.
"""

        return """Short answer:
No single top vulnerability was found in the current graph data.

Affected system:
No single affected asset is confirmed.

Why it matters:
The system needs asset, software, and vulnerability links before it can identify the most exposed vulnerability.

What to do:
Ask IT to confirm that the asset inventory and vulnerability data are loaded.

Evidence used:
This answer uses the current graph data, but no matching vulnerability exposure path was found.
"""

    if intent == "TOP_10_RISKS_HELP":
        data = execute_query(top_risks_query(10))
        if not data:
            return """Short answer:
No top risks were found in the current graph data.

What to do:
Ask IT to confirm that asset inventory and vulnerability data are loaded.

Evidence used:
Current graph data only.
"""

        lines = []
        for i, row in enumerate(data, start=1):
            software = ", ".join(row.get("software") or ["unknown software"])
            reason = risk_reason(row)
            lines.append(
                f"{i}. {row.get('asset_id')} ({row.get('hostname')}) - "
                f"{row.get('department', 'Unknown')} department, {row.get('subnet', 'Unknown')} subnet, "
                f"{row.get('criticality', 'Unknown')} business criticality. "
                f"{row.get('known_issues')} known software risk records, highest score {row.get('highest_score')}. "
                f"Main reason: {reason}. Software: {software}."
            )

        ranked_list = "\n".join(lines)
        return f"""Short answer:
These are the 10 assets that need the most attention in the current data. This is a risk ranking, not proof that these systems are under attack.

Top 10 risks:
{ranked_list}

Why it matters:
These systems have many known software risk records, high severity scores, or important network/business context. Reviewing the highest-ranked systems first can reduce company risk faster.

What to do:
Employees should use only trusted company apps and links, and report unusual pop-ups, login requests, slow systems, or suspicious messages to IT helpdesk. IT should prioritize patching and configuration review starting from item 1.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, asset criticality, and network context.
"""

    if intent == "MOST_VULNERABLE_SYSTEMS_HELP":
        data = execute_query(top_risks_query(5))
        if not data:
            return """Short answer:
No vulnerable systems were found in the current graph data.

What to do:
Ask IT to confirm that asset inventory and vulnerability data are loaded.

Evidence used:
Current graph data only.
"""

        lines = []
        for i, row in enumerate(data, start=1):
            software = ", ".join(row.get("software") or ["unknown software"])
            lines.append(
                f"{i}. {row.get('asset_id')} ({row.get('hostname')}) - "
                f"{row.get('department', 'Unknown')} department, {row.get('subnet', 'Unknown')} subnet, "
                f"{row.get('criticality', 'Unknown')} business criticality, "
                f"{row.get('known_issues')} known software risk records, highest score {row.get('highest_score')}. "
                f"Reason: {risk_reason(row)}. Software: {software}."
            )

        ranked_list = "\n".join(lines)
        return f"""Short answer:
These are the systems that need the most attention right now. This is based on known vulnerability records and business/network context, not proof of an active attack.

Most vulnerable systems:
{ranked_list}

Why it matters:
These systems have many known software risk records or very high severity scores. Reviewing the highest-ranked systems first helps reduce risk faster.

What to do:
Employees should use trusted company apps and links only, and report unusual errors, pop-ups, login requests, or suspicious messages to IT helpdesk. IT should prioritize patching and configuration review for the listed systems.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, asset criticality, and network context.
"""

    if intent == "HIGHEST_ISSUES_HELP":
        data = execute_query(highest_issues_query())
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
{top.get('asset_id')} has the highest number of known software risk records in the current data. This does not mean it is under attack; it means IT should review it first for updates and configuration fixes.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
This asset has {top.get('known_issues')} known software risk records, with the highest severity score listed as {top.get('highest_score')}. More records can mean more ways the system may need patching or safer settings.

What to do:
Employees should use trusted company apps and links only. Report unusual errors, pop-ups, login requests, or suspicious messages to IT helpdesk. IT should prioritize patching and configuration review for this asset.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
No asset issue count was found in the current graph data.

What to do:
Ask IT to confirm that asset inventory and vulnerability data are loaded.

Evidence used:
Current graph data only.
"""

    if intent == "SAFEST_SYSTEM_HELP":
        data = execute_query(safest_system_query())
        if data:
            row = data[0]
            software = ", ".join(row.get("software") or ["unknown software"])
            return f"""Short answer:
{row.get('asset_id')} appears to be the least risky system in the current data. This does not prove it is perfectly safe; it only has the lowest risk score among the systems currently loaded.

Affected system:
{row.get('asset_id')} ({row.get('hostname')}) in the {row.get('department', 'Unknown')} department, subnet {row.get('subnet', 'Unknown')}, running {software}.

Why it matters:
This system has {row.get('known_issues')} known software risk records, highest severity score {row.get('highest_score')}, {row.get('connected_systems')} connected systems, and {row.get('criticality', 'Unknown')} business criticality. Those factors make it lower risk than the other loaded systems.

What to do:
Keep using normal company safety habits: use trusted apps and links, avoid unexpected downloads or attachments, and report unusual pop-ups, errors, or login requests to IT helpdesk.

Evidence used:
Asset inventory, software list, vulnerability records, business criticality, and network context.
"""

        return """Short answer:
I could not identify the safest system from the current graph data.

Affected system:
No single system is confirmed.

Why it matters:
The assistant needs asset, software, vulnerability, and network records to rank safer systems.

What to do:
Ask IT to confirm that the asset inventory and vulnerability data are loaded.

Evidence used:
Current graph data only.
"""

    if intent == "ATTACK_EXPOSURE_HELP":
        data = execute_query(attack_exposure_query(5))
        if not data:
            return """Short answer:
No attack exposure was found in the current graph data.

Affected systems:
No single affected system is confirmed.

Why it matters:
Attack exposure means a system has known weaknesses, important network position, or connected systems that may need review.

What to do:
Ask IT to confirm that asset inventory, vulnerability data, and network data are loaded.

Evidence used:
Current graph data only.
"""

        lines = []
        for i, row in enumerate(data, start=1):
            software = ", ".join(row.get("software") or ["unknown software"])
            methods = ", ".join(row.get("possible_attack_methods") or ["known software weaknesses"])
            lines.append(
                f"{i}. {row.get('asset_id')} ({row.get('hostname')}) - "
                f"{row.get('department', 'Unknown')} department, {row.get('subnet', 'Unknown')} subnet, "
                f"{row.get('known_issues')} known software risk records, "
                f"{row.get('connected_systems')} connected systems. "
                f"Main exposure: {methods}. Software: {software}."
            )

        exposure_list = "\n".join(lines)
        return f"""Short answer:
These systems have the highest attack exposure in the current data. This is not proof of an active attack; it shows which systems IT should review first.

Systems with highest exposure:
{exposure_list}

Why it matters:
Exposure is higher when a system has known software risk records, is in an important network area, or is connected to other systems. Fixing these first can reduce the chance of business disruption.

What to do:
Employees should use trusted company apps and links only, and report unusual pop-ups, login requests, slow systems, or suspicious messages to IT helpdesk. IT should prioritize patching and configuration review for the listed systems.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, possible attack-method links, and network context.
"""

    if intent == "SOFTWARE_RISK_HELP":
        data = execute_query(software_risk_query(5))
        if not data:
            return """Short answer:
No software risk ranking was found in the current graph data.

Affected software:
No single software item is confirmed.

Why it matters:
The assistant needs software and vulnerability links before it can rank software risk.

What to do:
Ask IT to confirm that asset inventory, software inventory, and vulnerability data are loaded.

Evidence used:
Current graph data only.
"""

        lines = []
        for i, row in enumerate(data, start=1):
            assets = ", ".join(row.get("example_assets") or ["no asset listed"])
            cves = ", ".join(row.get("example_cves") or ["no CVE listed"])
            lines.append(
                f"{i}. {row.get('software')} - "
                f"found on {row.get('asset_count')} assets, "
                f"{row.get('known_issues')} known software risk records, "
                f"highest score {row.get('highest_score')}. "
                f"Example assets: {assets}. Example records: {cves}."
            )

        software_list = "\n".join(lines)
        return f"""Short answer:
These software items are causing the most risk in the current data. This does not mean they are currently being attacked; it means IT should review these software areas first.

Software causing most risk:
{software_list}

Why it matters:
Software risk is higher when the same software appears on several assets and has many known software risk records or very high severity scores.

What to do:
Employees should use trusted company apps and links only, and report unusual pop-ups, errors, slow behavior, or unexpected login requests to IT helpdesk. IT should prioritize updates and configuration review for the listed software.

Evidence used:
Software inventory, asset inventory, vulnerability records, and linked affected assets.
"""

    if intent == "RISKY_SOFTWARE_SYSTEMS_HELP":
        data = execute_query(risky_software_systems_query(5))
        if not data:
            return """Short answer:
No systems with risky software were found in the current graph data.

Affected systems:
No single affected system is confirmed.

Why it matters:
The assistant needs asset, software, and vulnerability links before it can identify risky software on systems.

What to do:
Ask IT to confirm that asset inventory, software inventory, and vulnerability data are loaded.

Evidence used:
Current graph data only.
"""

        lines = []
        for i, row in enumerate(data, start=1):
            software = ", ".join(row.get("risky_software") or ["unknown software"])
            cves = ", ".join(row.get("example_cves") or ["no CVE listed"])
            lines.append(
                f"{i}. {row.get('asset_id')} ({row.get('hostname')}) - "
                f"{row.get('department', 'Unknown')} department, {row.get('subnet', 'Unknown')} subnet, "
                f"{row.get('known_issues')} known software risk records, highest score {row.get('highest_score')}. "
                f"Risky software: {software}. Example records: {cves}."
            )

        system_list = "\n".join(lines)
        return f"""Short answer:
These systems have the riskiest software in the current data. This does not prove they are under attack; it means IT should review their software first.

Systems with risky software:
{system_list}

Why it matters:
Risky software means installed software has many known risk records or very high severity records. Updating or safely configuring that software can reduce risk.

What to do:
Employees should use trusted company apps and links only, and report unusual pop-ups, errors, slow behavior, or unexpected login requests to IT helpdesk. IT should prioritize patching and configuration review for the listed systems and software.

Evidence used:
Asset inventory, software inventory, vulnerability records, and network context.
"""

    if intent == "SYSTEM_SAFETY_HELP":
        data = execute_query(build_query("TOP_ASSETS"))
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
The current data cannot prove that your system is completely safe, and it also does not prove that an attack is happening right now. It shows known software risk records that IT should review.

Affected system:
The highest-priority system in the current data is {top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
Known software risk records mean the system may need updates or safer settings. A risk record is not the same as an active attack, but ignoring it can make a system easier to misuse later.

What to do:
Use only trusted company apps and links. Do not enter passwords into unexpected pop-ups or pages opened from messages. Report unusual errors, slow systems, unknown apps, or suspicious login requests to IT helpdesk.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
The current data cannot prove whether your system is fully safe because no matching asset risk records were found.

Affected system:
No single affected system is confirmed.

Why it matters:
Safety checks need asset inventory and vulnerability records. Without those records, the system can only give general safety advice.

What to do:
Use trusted company apps and links only. Report unusual pop-ups, login requests, unknown apps, or suspicious messages to IT helpdesk.

Evidence used:
Current graph data only.
"""

    if intent == "SERVER_RISK_HELP":
        data = execute_query(build_query("TOP_ASSETS"))
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
Yes, the current data shows risk records for a server, but it does not prove the server is under attack. The server IT should review first is {top.get('asset_id')}.

Affected system:
{top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
This server has {top.get('known_issues')} known software risk records, with the highest severity score listed as {top.get('highest_score')}. These records mean the server may need updates or safer settings.

What to do:
Use only trusted company apps and links. Report unusual errors, pop-ups, slow service, or unexpected login requests to IT helpdesk. Ask IT to prioritize patching and configuration review for {top.get('asset_id')}.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
The current data does not show a specific server risk record.

Affected system:
No single affected server is confirmed.

Why it matters:
Server risk checks need asset, software, and vulnerability records.

What to do:
Ask IT to confirm the server is included in the asset inventory and vulnerability data.

Evidence used:
Current graph data only.
"""

    if intent == "SYSTEM_CONCERN_HELP":
        data = execute_query(build_query("TOP_ASSETS"))
        if data:
            top = data[0]
            software = ", ".join(top.get("software") or ["unknown software"])
            cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])
            return f"""Short answer:
The current data cannot confirm that something is wrong with your system. It only shows known software risk records that IT should review; it does not prove an active attack or compromise.

Affected system:
The highest-priority system in the current data is {top.get('asset_id')} ({top.get('hostname')}) in the {top.get('department', 'Unknown')} department, subnet {top.get('subnet', 'Unknown')}, running {software}.

Why it matters:
Known software risk records mean a system may need updates or safer settings. Actual warning signs would be things like unusual pop-ups, unknown apps, repeated login requests, very slow behavior, or unexpected error messages.

What to do:
If you notice unusual behavior, report it to IT helpdesk with what happened and when it started. Do not open unknown links, attachments, or pop-ups. Keep using normal company apps unless IT tells you otherwise.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network context. Example records: {cves}.
"""

        return """Short answer:
The current data cannot confirm that something is wrong with your system.

Affected system:
No single affected system is confirmed.

Why it matters:
The question describes a possible concern, but no matching asset risk record was found in the current graph data.

What to do:
If you notice unusual pop-ups, unknown apps, repeated login requests, slow behavior, or unexpected errors, report it to IT helpdesk with the time and details.

Evidence used:
Current graph data only.
"""

    return None


def extract_asset_id(query):
    match = re.search(r"\bsrv-\d+\b", query.lower())
    return match.group(0).upper() if match else ""


def is_unclear_input(query):
    compact = re.sub(r"\s+", "", query.lower())
    if len(compact) < 4:
        return True

    known_terms = [
        "srv",
        "asset",
        "system",
        "server",
        "software",
        "risk",
        "vulner",
        "attack",
        "safe",
        "issue",
        "phishing",
        "malware",
        "ransomware",
        "sql",
        "mysql",
        "php",
        "apache",
        "nginx",
        "openssl",
        "windows",
        "ubuntu",
        "denial",
        "dos",
        "exposure",
        "compare",
        "wrong",
        "worried",
    ]
    if any(term in query for term in known_terms):
        return False

    vowels = sum(1 for char in compact if char in "aeiou")
    return vowels <= 1 or len(set(compact)) / max(len(compact), 1) > 0.8


def extract_asset_ids(query):
    return [match.upper() for match in re.findall(r"\bsrv-\d+\b", query.lower())][:2]


def extract_software_name(query):
    match = re.search(r"\bis\s+([a-z0-9 ._-]+?)\s+causing\s+(issues|risk|problems)\b", query.lower())
    return match.group(1).strip() if match else ""


def normalize_query_name(name):
    aliases = {
        "mysql": "mysql",
        "my sql": "mysql",
        "nodejs": "node",
        "node.js": "node",
        "windows server": "windows",
        "microsoft sql server": "sql",
    }
    cleaned = name.lower().strip()
    return aliases.get(cleaned, cleaned.replace(" ", "").replace("-", "").replace("_", ""))


def asset_risk_reason(row):
    reasons = []
    if row.get("criticality") in ["CRITICAL", "HIGH"]:
        reasons.append(f"it has {row.get('criticality').lower()} business importance")
    if row.get("subnet") == "DMZ":
        reasons.append("it is in the internet-facing DMZ area")
    elif row.get("subnet") == "DB":
        reasons.append("it is in the database area")
    if (row.get("highest_score") or 0) >= 9:
        reasons.append("it has very high severity software risk records")
    if (row.get("known_issues") or 0) >= 500:
        reasons.append("it has many known software risk records")
    if (row.get("connected_systems") or 0) > 0:
        reasons.append("it is connected to other systems")
    return ", ".join(reasons[:4]) if reasons else "it has known software risk records"


def risk_reason(row):
    reasons = []

    if row.get("criticality") in ["CRITICAL", "HIGH"]:
        reasons.append(f"{row.get('criticality').lower()} business importance")

    subnet = row.get("subnet")
    if subnet == "DMZ":
        reasons.append("internet-facing area")
    elif subnet == "DB":
        reasons.append("database area")

    if (row.get("highest_score") or 0) >= 9:
        reasons.append("very high severity issue")

    if (row.get("known_issues") or 0) >= 700:
        reasons.append("many known software risk records")

    if (row.get("connected_systems") or 0) >= 2:
        reasons.append("connected to other systems")

    return ", ".join(reasons[:3]) if reasons else "known software issues"


def sql_injection_query():
    return """
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WHERE cw.id = 'CWE-89'
       OR toLower(c.attack_type) CONTAINS 'sql injection'
       OR toLower(c.description) CONTAINS 'sql injection'
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
           collect(DISTINCT c.id)[0..5] AS example_cves,
           count(DISTINCT neighbor) AS connected_systems
    ORDER BY known_issues DESC, highest_score DESC, connected_systems DESC
    LIMIT 1
    """


def malware_risk_query():
    return """
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WHERE toLower(c.attack_type) CONTAINS 'malware'
       OR toLower(c.attack_type) CONTAINS 'ransomware'
       OR toLower(c.description) CONTAINS 'malware'
       OR toLower(c.description) CONTAINS 'ransomware'
       OR toLower(c.description) CONTAINS 'arbitrary code'
       OR toLower(c.description) CONTAINS 'code execution'
       OR toLower(c.description) CONTAINS 'remote code execution'
       OR toLower(c.description) CONTAINS 'command execution'
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
           collect(DISTINCT c.id)[0..5] AS example_cves,
           count(DISTINCT cw) AS weakness_count,
           count(DISTINCT neighbor) AS connected_systems
    ORDER BY known_issues DESC, highest_score DESC, connected_systems DESC
    LIMIT 1
    """


def ransomware_systems_query(limit):
    return f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WHERE toLower(c.attack_type) CONTAINS 'ransomware'
       OR toLower(c.description) CONTAINS 'ransomware'
       OR toLower(c.description) CONTAINS 'remote code execution'
       OR toLower(c.description) CONTAINS 'arbitrary code'
       OR toLower(c.description) CONTAINS 'code execution'
       OR toLower(c.description) CONTAINS 'command execution'
       OR toLower(c.description) CONTAINS 'privilege escalation'
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
           count(DISTINCT cw) AS weakness_count,
           count(DISTINCT neighbor) AS connected_systems
    ORDER BY known_issues DESC, highest_score DESC, connected_systems DESC
    LIMIT {int(limit)}
    """


def dos_risk_query(limit=1):
    return f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WHERE cw.id = 'CWE-400'
       OR toLower(c.attack_type) CONTAINS 'dos'
       OR toLower(c.attack_type) CONTAINS 'denial of service'
       OR toLower(c.description) CONTAINS 'denial of service'
       OR toLower(c.description) CONTAINS 'resource exhaustion'
       OR toLower(c.description) CONTAINS 'unavailable'
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
           collect(DISTINCT c.id)[0..5] AS example_cves,
           count(DISTINCT cw) AS weakness_count,
           count(DISTINCT neighbor) AS connected_systems
    ORDER BY known_issues DESC, highest_score DESC, connected_systems DESC
    LIMIT {int(limit)}
    """


def most_exposed_vulnerability_query():
    return """
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WITH a, c, sn,
         collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
         collect(DISTINCT cw.id)[0] AS weakness_id,
         collect(DISTINCT cw.name)[0] AS weakness_name,
         count(DISTINCT neighbor) AS connected_systems
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           software,
           c.id AS cve_id,
           c.description AS description,
           c.severity AS severity,
           c.cvss AS cvss,
           weakness_id,
           weakness_name,
           connected_systems
    ORDER BY c.cvss DESC, connected_systems DESC
    LIMIT 1
    """


def top_risks_query(limit):
    return f"""
    MATCH (a:Asset)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    CALL (a) {{
        MATCH (a)-[r:AFFECTED_BY]->(c:CVE)
        RETURN count(DISTINCT c) AS known_issues,
               max(c.cvss) AS highest_score,
               collect(DISTINCT coalesce(r.software_raw, r.software))[0..4] AS software,
               collect(DISTINCT c.id)[0..5] AS example_cves,
               sum(CASE c.severity
                   WHEN 'CRITICAL' THEN 5
                   WHEN 'HIGH' THEN 3
                   WHEN 'MEDIUM' THEN 1
                   ELSE 0
               END * CASE r.confidence
                   WHEN 'high' THEN 1.5
                   WHEN 'medium' THEN 1.0
                   ELSE 0.5
               END) AS weighted_vuln_score
    }}
    CALL (a) {{
        OPTIONAL MATCH (a)-[:AFFECTED_BY]->(:CVE)-[:HAS_WEAKNESS]->(cw:CWE)
        RETURN count(DISTINCT cw) AS weakness_count,
               collect(DISTINCT cw.id)[0..5] AS weakness_ids,
               collect(DISTINCT cw.name)[0..5] AS weakness_names
    }}
    CALL (a) {{
        OPTIONAL MATCH (a)-[:AFFECTED_BY]->(:CVE)-[:HAS_WEAKNESS]->(:CWE)-[:EXPLOITED_BY]->(t:ATTACK)
        RETURN count(DISTINCT t) AS attack_method_count,
               collect(DISTINCT t.name)[0..5] AS possible_attack_methods
    }}
    CALL (a) {{
        OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
        RETURN count(DISTINCT neighbor) AS connected_systems
    }}
    WITH a, sn, known_issues, highest_score, weakness_count, attack_method_count,
         connected_systems, software, example_cves, weakness_ids, weakness_names,
         possible_attack_methods, weighted_vuln_score,
         CASE a.criticality
             WHEN 'CRITICAL' THEN 1.5
             WHEN 'HIGH' THEN 1.25
             WHEN 'MEDIUM' THEN 1.0
             ELSE 0.8
         END AS criticality_weight,
         CASE sn.id
             WHEN 'DMZ' THEN 30
             WHEN 'DB' THEN 20
             ELSE 10
         END AS subnet_weight
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           known_issues,
           round(highest_score * 10) / 10 AS highest_score,
           weakness_count,
           attack_method_count,
           connected_systems,
           software,
           example_cves,
           weakness_ids,
           weakness_names,
           possible_attack_methods,
           round((weighted_vuln_score + weakness_count + attack_method_count + connected_systems + subnet_weight) * criticality_weight) AS risk_rank_score
    ORDER BY risk_rank_score DESC, highest_score DESC
    LIMIT {int(limit)}
    """


def highest_issues_query():
    return """
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
           collect(DISTINCT c.id)[0..5] AS example_cves,
           count(DISTINCT cw) AS weakness_count
    ORDER BY known_issues DESC, highest_score DESC
    LIMIT 1
    """


def attack_exposure_query(limit):
    return f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (cw)-[:EXPLOITED_BY]->(t:ATTACK)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WITH a, sn,
         count(DISTINCT c) AS known_issues,
         max(c.cvss) AS highest_score,
         count(DISTINCT cw) AS weakness_count,
         count(DISTINCT t) AS attack_method_count,
         count(DISTINCT neighbor) AS connected_systems,
         collect(DISTINCT t.name)[0..3] AS possible_attack_methods,
         collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           known_issues,
           round(highest_score * 10) / 10 AS highest_score,
           weakness_count,
           attack_method_count,
           connected_systems,
           possible_attack_methods,
           software,
           (attack_method_count * 3 + connected_systems * 2 + weakness_count + known_issues) AS exposure_score
    ORDER BY exposure_score DESC, highest_score DESC
    LIMIT {int(limit)}
    """


def most_likely_attack_query(limit):
    return f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)-[:HAS_WEAKNESS]->(cw:CWE)-[:EXPLOITED_BY]->(t:ATTACK)
    WITH t,
         count(DISTINCT c) AS known_issues,
         count(DISTINCT a) AS asset_count,
         max(c.cvss) AS highest_score,
         collect(DISTINCT a.id)[0..5] AS example_assets,
         collect(DISTINCT cw.id)[0..5] AS weakness_ids,
         collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software
    RETURN t.name AS attack_type,
           known_issues,
           asset_count,
           round(highest_score * 10) / 10 AS highest_score,
           example_assets,
           weakness_ids,
           software
    ORDER BY known_issues DESC, highest_score DESC, asset_count DESC
    LIMIT {int(limit)}
    """


def software_risk_query(limit):
    return f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    WITH coalesce(r.software_raw, r.software) AS software,
         count(DISTINCT a) AS asset_count,
         count(DISTINCT c) AS known_issues,
         max(c.cvss) AS highest_score,
         collect(DISTINCT a.id)[0..5] AS example_assets,
         collect(DISTINCT c.id)[0..5] AS example_cves
    RETURN software,
           asset_count,
           known_issues,
           round(highest_score * 10) / 10 AS highest_score,
           example_assets,
           example_cves,
           (known_issues + asset_count * 20 + highest_score * 10) AS software_risk_score
    ORDER BY software_risk_score DESC, highest_score DESC
    LIMIT {int(limit)}
    """


def risky_software_systems_query(limit):
    return f"""
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    WITH a, sn, coalesce(r.software_raw, r.software) AS software,
         count(DISTINCT c) AS software_issue_count,
         max(c.cvss) AS software_highest_score,
         collect(DISTINCT c.id)[0..3] AS cves_for_software
    ORDER BY software_issue_count DESC, software_highest_score DESC
    WITH a, sn,
         sum(software_issue_count) AS known_issues,
         max(software_highest_score) AS highest_score,
         collect(DISTINCT software)[0..5] AS risky_software,
         collect(cves_for_software)[0..3] AS cve_groups
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           known_issues,
           round(highest_score * 10) / 10 AS highest_score,
           risky_software,
           reduce(flat = [], group IN cve_groups | flat + group)[0..5] AS example_cves
    ORDER BY known_issues DESC, highest_score DESC
    LIMIT {int(limit)}
    """


def specific_software_risk_query():
    return """
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    WHERE r.software = $software
       OR r.software CONTAINS $software
    RETURN coalesce(r.software_raw, r.software) AS software,
           count(DISTINCT a) AS asset_count,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           collect(DISTINCT a.id)[0..5] AS example_assets,
           collect(DISTINCT c.id)[0..5] AS example_cves
    ORDER BY known_issues DESC
    LIMIT 1
    """


def asset_risk_explanation_query():
    return """
    MATCH (a:Asset {id:$asset_id})-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           count(DISTINCT cw) AS weakness_count,
           count(DISTINCT neighbor) AS connected_systems,
           collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
           collect(DISTINCT c.id)[0..5] AS example_cves
    """


def compare_assets_query():
    return """
    MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
    WHERE a.id IN $asset_ids
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WITH a, sn,
         count(DISTINCT c) AS known_issues,
         max(c.cvss) AS highest_score,
         count(DISTINCT neighbor) AS connected_systems,
         collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software
    WITH a, sn, known_issues, highest_score, connected_systems, software,
         CASE a.criticality
             WHEN 'CRITICAL' THEN 1.5
             WHEN 'HIGH' THEN 1.25
             WHEN 'MEDIUM' THEN 1.0
             ELSE 0.8
         END AS criticality_weight,
         CASE sn.id
             WHEN 'DMZ' THEN 30
             WHEN 'DB' THEN 20
             ELSE 10
         END AS subnet_weight
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           known_issues,
           round(highest_score * 10) / 10 AS highest_score,
           connected_systems,
           software,
           round((known_issues + highest_score * 10 + connected_systems * 10 + subnet_weight) * criticality_weight) AS risk_score
    """


def safest_system_query():
    return """
    MATCH (a:Asset)
    OPTIONAL MATCH (a)-[r:AFFECTED_BY]->(c:CVE)
    OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
    OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
    WITH a, sn,
         count(DISTINCT c) AS known_issues,
         coalesce(max(c.cvss), 0) AS highest_score,
         count(DISTINCT neighbor) AS connected_systems,
         collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software
    WITH a, sn, known_issues, highest_score, connected_systems, software,
         CASE a.criticality
             WHEN 'CRITICAL' THEN 1.5
             WHEN 'HIGH' THEN 1.25
             WHEN 'MEDIUM' THEN 1.0
             ELSE 0.8
         END AS criticality_weight,
         CASE sn.id
             WHEN 'DMZ' THEN 30
             WHEN 'DB' THEN 20
             ELSE 10
         END AS subnet_weight
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           known_issues,
           round(highest_score * 10) / 10 AS highest_score,
           connected_systems,
           software,
           round((known_issues + highest_score * 10 + connected_systems * 10 + subnet_weight) * criticality_weight) AS risk_score
    ORDER BY risk_score ASC, known_issues ASC
    LIMIT 1
    """


def map_to_attack(query):
    q = query.lower()
    mapping = {
        "phishing": ["Phishing"],
        "phising": ["Phishing"],
        "malware": ["Malware"],
        "virus": ["Malware"],
        "ransomware": ["Malware"],
        "ddos": ["Endpoint Denial of Service"],
        "dos": ["Endpoint Denial of Service"],
        "denial of service": ["Endpoint Denial of Service"],
        "command": ["Command and Scripting Interpreter"],
        "injection": ["Command and Scripting Interpreter"],
    }

    matches = []
    for key, vals in mapping.items():
        if key in q:
            matches.extend(vals)

    return sorted(set(matches))


def build_query(intent):
    common_return = """
    RETURN a.id AS asset_id,
           a.hostname AS hostname,
           a.ip AS ip,
           a.department AS department,
           a.criticality AS criticality,
           sn.id AS subnet,
           count(DISTINCT c) AS known_issues,
           round(max(c.cvss) * 10) / 10 AS highest_score,
           collect(DISTINCT coalesce(r.software_raw, r.software))[0..5] AS software,
           collect(DISTINCT c.id)[0..5] AS example_cves,
           collect(DISTINCT cw.id)[0..5] AS weakness_ids,
           collect(DISTINCT cw.name)[0..5] AS weakness_names,
           collect(DISTINCT t.name)[0..5] AS possible_attack_methods,
           count(DISTINCT neighbor) AS connected_systems
    """

    if intent == "ASSET_DRILLDOWN":
        return """
        MATCH (a:Asset {id: $asset_id})-[r:AFFECTED_BY]->(c:CVE)
        RETURN a.id AS asset,
               coalesce(r.software_raw, r.software) AS software,
               COUNT(DISTINCT c) AS vuln_count,
               count(CASE WHEN r.confidence = 'high' THEN 1 END) AS high_confidence,
               count(CASE WHEN r.confidence = 'medium' THEN 1 END) AS medium_confidence,
               count(CASE WHEN r.confidence = 'low' THEN 1 END) AS low_confidence
        ORDER BY vuln_count DESC
        LIMIT 5
        """

    if intent == "TOP_ASSETS":
        return top_risks_query(3)

    if intent == "ATTACK_SURFACE":
        return (
            """
            MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
            OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
            OPTIONAL MATCH (cw)-[:EXPLOITED_BY]->(t:ATTACK)
            OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
            OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
            WHERE sn.type IN ['internet-facing', 'restricted'] OR neighbor IS NOT NULL
            """
            + common_return
            + """
            ORDER BY connected_systems DESC, known_issues DESC
            LIMIT 3
            """
        )

    if intent == "ATTACK_QUERY":
        return (
            """
            MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
            MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)-[:EXPLOITED_BY]->(t:ATTACK)
            OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
            OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
            WHERE t.name IN $attack_list
            """
            + common_return
            + """
            ORDER BY known_issues DESC, highest_score DESC
            LIMIT 3
            """
        )

    return (
        """
        MATCH (a:Asset)-[r:AFFECTED_BY]->(c:CVE)
        OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(cw:CWE)
        OPTIONAL MATCH (cw)-[:EXPLOITED_BY]->(t:ATTACK)
        OPTIONAL MATCH (a)-[:IN_SUBNET]->(sn:Subnet)
        OPTIONAL MATCH (a)-[:CONNECTED_TO]-(neighbor:Asset)
        """
        + common_return
        + """
        ORDER BY highest_score DESC, known_issues DESC
        LIMIT 3
        """
    )


def execute_query(query, params=None):
    with driver.session() as session:
        result = session.run(query, params or {})
        return [dict(r) for r in result]


def compute_confidence(data):
    if not data:
        return "Low"

    counts = [
        d.get("issues")
        or d.get("vuln_count")
        or d.get("known_issues")
        or d.get("weighted_risk")
        or d.get("risk_rank_score")
        or d.get("risk_score")
        or 0
        for d in data
    ]

    counts = [count for count in counts if isinstance(count, (int, float))]
    if not counts:
        return "Low"

    max_count = max(counts)
    avg_count = sum(counts) / len(counts)

    if avg_count == 0:
        return "Low"

    if max_count > avg_count * 1.5:
        return "High"

    if max_count > avg_count:
        return "Medium"

    return "Low"


def plain_context(user_query):
    if not VECTOR_INDEX:
        return []
    return retrieve(user_query, VECTOR_INDEX, VECTOR_TEXTS)


def is_asset_drilldown_data(data):
    return bool(data) and {"asset", "software", "vuln_count"}.issubset(data[0].keys())


def explain_asset_drilldown(data, confidence):
    asset = data[0].get("asset", "Unknown asset")
    top = data[0]
    secondary = data[1] if len(data) > 1 else None
    total = sum(row.get("vuln_count") or 0 for row in data)

    if top.get("vuln_count", 0) >= 300:
        risk_level = "High"
    elif top.get("vuln_count", 0) >= 100:
        risk_level = "Moderate"
    else:
        risk_level = "Low"

    causes = [
        f"- {top.get('software')} has the highest number of linked software risk records: {top.get('vuln_count')}."
    ]
    if secondary:
        causes.append(
            f"- {secondary.get('software')} also contributes risk with {secondary.get('vuln_count')} linked records."
        )
    causes.append(f"- These counts are based on available CPE/product evidence and relationship confidence.")

    return f"""Asset:
{asset}

Main causes:
{chr(10).join(causes)}

Why it matters:
More linked software risk records mean IT may need to review updates or safer settings. The software with the highest count should be checked first.

What we don't know:
The data does not show whether anyone is actively misusing this system. There is no clear sign of an ongoing attack right now.

Risk level:
{risk_level}

Confidence:
{confidence} - based on available system data, not real-time monitoring.

What to do:
Use trusted company apps and links only. Ask IT to prioritize the highest-count software listed above.
"""


def explain_result(user_query, data, confidence):
    if is_asset_drilldown_data(data):
        return explain_asset_drilldown(data, confidence)

    context = plain_context(user_query)

    prompt = f"""
You are helping a company employee understand why a specific system may be risky.

STRICT RULES:
- Use ONLY the provided Asset Data
- Do NOT invent software, CVEs, departments, or any details not present
- Do NOT assume anything beyond data
- Do NOT mention logs, alerts, monitoring, or investigation
- Do NOT give advanced cybersecurity advice
- Do NOT mention forensic tools, packet capture, SIEM tools, or specialist software
- Do NOT say attacks can spread, steal data, gain control, or compromise systems unless the provided data explicitly says that
- Use simple, clear, non-technical language
- Keep explanation structured and easy to read
- Total length: 8-10 lines maximum

User Question:
{user_query}

Asset Data:
{data}

Helpful Info:
{context}

Your job:
Explain WHY this system is risky based strictly on the data.

OUTPUT FORMAT (follow exactly):
Asset:
(mention asset id)

Main causes:
- (Cause 1 based on data, e.g. software with high issues)
- (Cause 2 based on data)
- (Optional Cause 3)

Why it matters:
(2 short sentences explaining impact)

What we don't know:
(1-2 short sentences clearly stating uncertainty)

Risk level:
(Low / Moderate / High based ONLY on relative issue count)

Confidence:
({confidence} - based on available system data, not real-time monitoring)

What to do:
(1-2 simple precautions a normal employee can follow)

MANDATORY:
- You MUST include this exact sentence:
"There is no clear sign of an ongoing attack right now."

- If multiple software are present, highlight the one with highest issues
- If data is limited, say so clearly instead of guessing

Evidence used:
(list data sources in one short sentence)
"""

    try:
        response = ollama.chat(
            model="llama3",
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception:
        return fallback_explanation(data, confidence)

    output = response["message"]["content"].strip()
    forbidden_terms = [
        "investigation",
        "logs",
        "alerts",
        "monitoring",
        "forensic",
        "packet capture",
        "siem",
        "spread an attack",
        "steal data",
        "gain control",
        "compromise systems",
        "compromised",
        "attack methods",
        "exploit these vulnerabilities",
        "exploited",
        "vulnerable to attacks",
        "security incidents",
        "troubleshoot",
    ]
    if (
        output
        and "There is no clear sign of an ongoing attack right now." in output
        and not any(term in output.lower() for term in forbidden_terms)
    ):
        return output

    return fallback_explanation(data, confidence)


def fallback_explanation(data, confidence):
    top = data[0]
    software = ", ".join(top.get("software") or ["unknown software"])
    cves = ", ".join(top.get("example_cves") or ["no example CVE listed"])

    return f"""Asset:
{top.get('asset_id')} ({top.get('hostname') or 'unknown hostname'})

Main causes:
- Department: {top.get('department', 'Unknown')}; subnet: {top.get('subnet', 'Unknown')}.
- Software listed for this asset: {software}.
- Example vulnerability records: {cves}.

Why it matters:
Known software risk records mean the system may need updates or safer settings. The highest listed severity score is {top.get('highest_score', 'unknown')}.

What we don't know:
The data does not show whether anyone is actively misusing this system. There is no clear sign of an ongoing attack right now.

Risk level:
Review needed based on the current asset and vulnerability data.

Confidence:
{confidence} - based on available system data, not real-time observation.

What to do:
Use trusted company apps and links only. Ask IT to prioritize patching and configuration review for this asset.

Evidence used:
Asset inventory, software list, vulnerability records, weakness records, and network/SBOM context.
"""


def answer_question(user_query):
    intent = detect_intent(user_query)
    direct_answer = direct_employee_answer(intent, user_query)
    if direct_answer:
        return direct_answer

    query = build_query(intent)
    params = {}

    if intent == "ASSET_DRILLDOWN":
        asset_id = extract_asset_id(user_query)
        if not asset_id:
            return """Short answer:
I could not identify the asset ID in your question.

Affected system:
No specific asset is confirmed.

Why it matters:
The assistant needs an asset ID like SRV-032 to explain why a specific system may be risky.

What to do:
Ask again with the asset ID, for example: why is SRV-032 risky?

Evidence used:
No graph data was used because no asset ID was found.
"""
        params["asset_id"] = asset_id

    if intent == "ATTACK_QUERY":
        attack_list = map_to_attack(user_query)
        if not attack_list:
            return """Short answer:
I do not recognize that attack type in the current security knowledge graph, so I cannot say which asset is vulnerable to it.

Affected system:
No affected asset is confirmed.

Why it matters:
The assistant should only answer from known asset, software, vulnerability, and attack-mapping data. If an attack type is not mapped, guessing would be misleading.

What to do:
Ask with a known risk type such as phishing, malware, ransomware, SQL injection, or denial of service. If this is a real concern, report the exact message, file, link, or behavior to IT helpdesk.

Evidence used:
Current attack mapping and graph data only.
"""
        params["attack_list"] = attack_list

    data = execute_query(query, params)

    if not data:
        if intent == "ASSET_DRILLDOWN":
            return """Asset:
Not found

Main causes:
- No software risk records were found for the requested asset.

Why it matters:
The asset ID may be missing from the graph, or it may not have linked software and vulnerability records.

What we don't know:
The data is limited for this asset. There is no clear sign of an ongoing attack right now.

Risk level:
Unknown

Confidence:
Low - based on available system data, not real-time monitoring.

What to do:
Ask IT to confirm the asset ID and whether the latest asset and vulnerability data are loaded.
"""
        return "No matching risk was found in the current asset and vulnerability data."

    confidence = compute_confidence(data)
    return explain_result(user_query, data, confidence)


def main():
    print("\nCyber Assistant - employee-friendly security answers\n")

    while True:
        user_query = input("Ask: ")

        if user_query.lower() == "exit":
            break

        intent = detect_intent(user_query)
        direct_answer = direct_employee_answer(intent, user_query)
        if direct_answer:
            print("\nExplanation:\n")
            print(direct_answer)
            print("\n" + "=" * 60 + "\n")
            continue

        query = build_query(intent)
        params = {}

        if intent == "ASSET_DRILLDOWN":
            asset_id = extract_asset_id(user_query)
            if not asset_id:
                print("""Explanation:

Short answer:
I could not identify the asset ID in your question.

Affected system:
No specific asset is confirmed.

Why it matters:
The assistant needs an asset ID like SRV-032 to explain why a specific system may be risky.

What to do:
Ask again with the asset ID, for example: why is SRV-032 risky?

Evidence used:
No graph data was used because no asset ID was found.
""")
                continue
            params["asset_id"] = asset_id

        if intent == "ATTACK_QUERY":
            attack_list = map_to_attack(user_query)
            if not attack_list:
                print("""Explanation:

Short answer:
I do not recognize that attack type in the current security knowledge graph, so I cannot say which asset is vulnerable to it.

Affected system:
No affected asset is confirmed.

Why it matters:
The assistant should only answer from known asset, software, vulnerability, and attack-mapping data. If an attack type is not mapped, guessing would be misleading.

What to do:
Ask with a known risk type such as phishing, malware, ransomware, SQL injection, or denial of service. If this is a real concern, report the exact message, file, link, or behavior to IT helpdesk.

Evidence used:
Current attack mapping and graph data only.
""")
                continue
            params["attack_list"] = attack_list

        data = execute_query(query, params)

        if not data:
            if intent == "ASSET_DRILLDOWN":
                confidence = compute_confidence(data)
                print("""Explanation:

Asset:
Not found

Main causes:
- No software risk records were found for the requested asset.

Why it matters:
The asset ID may be missing from the graph, or it may not have linked software and vulnerability records.

What we don't know:
The data is limited for this asset. There is no clear sign of an ongoing attack right now.

Risk level:
Unknown

Confidence:
Low - based on available system data, not real-time monitoring.

What to do:
Ask IT to confirm the asset ID and whether the latest asset and vulnerability data are loaded.
""")
                continue
            print("No matching risk was found in the current asset and vulnerability data.\n")
            continue

        print("\nExplanation:\n")
        confidence = compute_confidence(data)
        print(explain_result(user_query, data, confidence))
        print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()

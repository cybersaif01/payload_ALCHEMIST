def analyze_response(results, attack_type):
    print(f"[Detector] Scanning responses for indicators of {attack_type.upper()} exploitation")
    findings = []

    xss_signatures = [
        "<script>", "onerror=", "alert(", "<svg", "<img", "javascript:", "<iframe", "onload=", "ontoggle=", "onfocus=", "<object"
    ]

    sqli_signatures = [
        "SQL syntax", "mysql_fetch", "ORA-01756", "Warning: sqlite_", "unclosed quotation mark", "You have an error in your SQL syntax"
    ]

    for entry in results:
        response = entry.get("response_snippet", "").lower()
        confidence = "low"
        evidence = []

        if attack_type == "xss":
            evidence = [sig for sig in xss_signatures if sig.lower() in response]
        elif attack_type == "sqli":
            evidence = [sig for sig in sqli_signatures if sig.lower() in response]

        if evidence:
            confidence = "medium" if len(evidence) <= 2 else "high"

        entry.update({
            "evidence": evidence,
            "confidence": confidence
        })

        findings.append(entry)

    return findings

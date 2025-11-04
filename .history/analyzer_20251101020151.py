def summarize_findings(findings: list[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    Produce tiny, human-friendly counts per rule and per severity.

    Args:
        findings: The list returned by analyze(snapshot).

    Returns:
        A dict with two maps: {"by_rule": {...}, "by_severity": {...}}
    """
    by_rule: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_rule[f.get("rule", "?")] = by_rule.get(f.get("rule", "?"), 0) + 1
        by_sev[f.get("severity", "INFO")] = by_sev.get(f.get("severity", "INFO"), 0) + 1
    return {"by_rule": by_rule, "by_severity": by_sev}

























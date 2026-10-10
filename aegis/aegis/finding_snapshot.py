"""Reuse the established read-only finding projection, never recovery reads."""

from aegis.findings_report import build_report


def require_finding(campaign, finding_id):
    # Schema 1 validation also rejects unfinished or contradictory triage data.
    for item in build_report(campaign)['findings']:
        if item['record']['finding_id'] == finding_id:
            return item['record']
    raise LookupError(f'Finding not found: {finding_id}')

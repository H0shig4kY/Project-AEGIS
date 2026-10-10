"""Read-only projection of persisted findings; never run recovery or scans."""

import errno
import json
import os
import re
import tempfile
import unicodedata
from contextlib import ExitStack
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import yaml

from aegis import triage_journal
from aegis.atomic_storage import StorageIntegrityError, directory_lock, read_json
from aegis.context import CampaignContext
from aegis.finding_history_store import FindingHistoryStore
from aegis.finding_store import FindingStore
from aegis.models import FindingState, FindingTriageState


class ReportFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"


def _json_paths(directory):
    """Only an absent directory is empty; never suppress enumeration failures."""
    try:
        try:
            scan = os.scandir(directory)
        except FileNotFoundError:
            # A dangling directory symlink is invalid storage, not legacy absence.
            try:
                directory.lstat()
            except FileNotFoundError:
                return []
            raise
        with scan:
            return sorted(directory / entry.name for entry in scan
                          if os.path.normcase(entry.name).endswith(".json"))
    except OSError as error:
        raise StorageIntegrityError(f"Cannot enumerate storage directory {directory}: {error}") from error


def _event_key(payload):
    timestamp = datetime.fromisoformat(payload["detected_at"])
    # Keep legacy naive timestamps unchanged in output. Their timezone is unknown.
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    return timestamp, payload["event_id"]


def _history(directory, records, *, operational):
    events = {}
    for path in _json_paths(directory):
        try:
            payload = read_json(path)
            if operational:
                event = triage_journal._decode_event(payload)
                if not re.fullmatch(r"[0-9a-f]{32}", event.event_id):
                    raise ValueError("invalid triage event ID")
            else:
                event = FindingHistoryStore._load(path)
            if event.event_id != path.stem:
                raise ValueError("event ID/filename mismatch")
            if event.finding_id not in records:
                raise ValueError("event references a missing finding")
            _event_key(payload)  # Validate that the stored timestamp can be ordered.
            events[event.event_id] = payload
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError) as error:
            raise StorageIntegrityError(f"Invalid history in {path}: {error}") from error
    return events


def _validate_journal(entries, records, histories):
    latest = {}
    for path, receipt in entries:
        event = receipt["event"]
        directory = (path.parent.parent / receipt["history_directory"]).resolve()
        existing = histories[directory].get(event["event_id"])
        if receipt["status"] == "aborted":
            if existing is not None:
                raise StorageIntegrityError(f"Aborted receipt has an audit event: {path}")
        elif existing != event:
            raise StorageIntegrityError(f"Missing or conflicting triage event for {path}")
        latest[event["finding_id"]] = receipt
    for finding_id, receipt in latest.items():
        record = records.get(finding_id)
        expected = receipt["event"][
            "from_state" if receipt["status"] == "aborted" else "to_state"]
        if record is None or record.triage_state.value != expected:
            raise StorageIntegrityError(f"Finding/journal state divergence: {finding_id}")


def _group_history(events):
    grouped = {}
    for event in events.values():
        grouped.setdefault(event["finding_id"], []).append(event)
    for timeline in grouped.values():
        timeline.sort(key=_event_key)
    return grouped


def build_report(campaign: CampaignContext, *, generated_at: datetime | None = None,
                 schema_version: int = 1) -> dict:
    """Read and validate a complete snapshot, raising instead of repairing data."""
    generated_at = generated_at or datetime.now(timezone.utc)
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise ValueError('Supported report schema versions are 1 and 2')
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    with directory_lock(campaign.findings_dir, create=False):
        entries = triage_journal.inspect_completed(campaign.findings_dir)
        directories = {campaign.finding_triage_history_dir.resolve()}
        directories.update((campaign.findings_dir / data["history_directory"]).resolve()
                           for _, data in entries)
        # Match writers: finding first, then technical/operational histories.
        with ExitStack() as stack:
            for directory in sorted(directories | {campaign.finding_history_dir.resolve()}, key=str):
                stack.enter_context(directory_lock(directory, create=False))
            stack.enter_context(directory_lock(campaign.path, create=False))
            try:
                config = yaml.safe_load(campaign.config_file.read_text(encoding="utf-8"))
                if not isinstance(config, dict):
                    raise ValueError("assessment configuration must be a mapping")
                if "name" in config and config["name"] is not None and not isinstance(config["name"], str):
                    raise ValueError("assessment name must be a string or null")
            except (yaml.YAMLError, ValueError, UnicodeError, RecursionError) as error:
                raise StorageIntegrityError(f"Invalid assessment configuration: {error}") from error
            records = {}
            sources = {}
            for path in _json_paths(campaign.findings_dir):
                try:
                    source = read_json(path)
                    record = FindingStore._deserialize(source)
                    if record.finding_id != path.stem:
                        raise ValueError("finding ID/filename mismatch")
                    records[record.finding_id] = record
                    sources[record.finding_id] = source
                except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError) as error:
                    raise StorageIntegrityError(f"Invalid finding in {path}: {error}") from error
            technical = _history(campaign.finding_history_dir, records, operational=False)
            histories = {directory: _history(directory, records, operational=True)
                         for directory in directories}
            _validate_journal(entries, records, histories)
            operational = {}
            for events in histories.values():
                for event_id, event in events.items():
                    if event_id in operational and operational[event_id] != event:
                        raise StorageIntegrityError(f"Conflicting triage event ID: {event_id}")
                    operational[event_id] = event
            technical_by_finding = _group_history(technical)
            operational_by_finding = _group_history(operational)
            summary = {"total": len(records), "by_state": {s.value: 0 for s in FindingState},
                       "by_triage_state": {s.value: 0 for s in FindingTriageState}}
            findings = []
            for finding_id, record in sorted(records.items()):
                normalized = FindingStore._serialize(record)
                source = sources[finding_id]
                summary["by_state"][record.state.value] += 1
                summary["by_triage_state"][record.triage_state.value] += 1
                findings.append({
                    "record": normalized,
                    "source_fields": sorted(source),
                    "source_extensions": {k: v for k, v in source.items() if k not in normalized},
                    "technical_history": technical_by_finding.get(finding_id, []),
                    "triage_history": operational_by_finding.get(finding_id, []),
                })
            result = {"schema_version": 1,
                      "assessment": {"name": config["name"]} if "name" in config else {},
                      "generated_at": generated_at.astimezone(timezone.utc).isoformat(),
                      "summary": summary, "findings": findings}
            if schema_version == 2:
                from aegis.evidence_store import EvidenceReader
                evidence_by_finding = {}
                verified = EvidenceReader(campaign).all_verified()
                for record, verification in verified:
                    if record.finding_id not in records:
                        raise StorageIntegrityError(f'Evidence references a missing finding: {record.evidence_id}')
                    metadata = record.model_dump(mode='json')
                    # Basenames remain private; hashes identify stored provenance.
                    metadata['origin'].pop('source_name', None)
                    metadata['origin'].pop('result_filename', None)
                    evidence_by_finding.setdefault(record.finding_id, []).append({
                        'metadata': metadata, 'verification': verification})
                for item in findings:
                    item['evidence'] = evidence_by_finding.get(item['record']['finding_id'], [])
                result['schema_version'] = 2
                summary['evidence'] = {'associations': len(verified),
                    'captured': sum(r.content_sha256 is not None for r, _ in verified),
                    'external_references': sum(r.content_sha256 is None for r, _ in verified)}
            # Validate the full export, including opaque extensions, before any output.
            try:
                render_json(result)
            except (ValueError, TypeError, RecursionError) as error:
                raise StorageIntegrityError(f"Source data cannot be exported as strict UTF-8 JSON: {error}") from error
    return result


def render_json(report: dict) -> str:
    content = json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"
    content.encode("utf-8")
    return content


def _literal(value) -> str:
    """Literal text entities prevent Markdown, HTML, links and line injection."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    result = []
    for char in text:
        if unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
            result.append(f"U+{ord(char):04X}")
        elif char.isalnum() or char == " ":
            result.append(char)
        else:
            result.append(f"&#{ord(char)};")
    return "".join(result)


def render_markdown(report: dict) -> str:
    lines = ["# AEGIS findings report", "", f"Schema version: {report['schema_version']}",
             f"Generated at: {_literal(report['generated_at'])}", "", "## Assessment", ""]
    if "name" in report["assessment"]:
        lines.append(f"Name: {_literal(report['assessment']['name'])}")
    else:
        lines.append("Name: absent in source configuration")
    lines.extend(["", "## Summary", "", f"Total: {report['summary']['total']}", ""])
    for category in ("by_state", "by_triage_state"):
        lines.append(f"### {category}")
        lines.append("")
        for key, count in sorted(report["summary"][category].items()):
            lines.append(f"- {_literal(key)}: {count}")
        lines.append("")
    for item in report["findings"]:
        lines.extend([f"## Finding {_literal(item['record']['finding_id'])}", ""])
        for key, value in sorted(item["record"].items()):
            lines.append(f"- {_literal(key)}: {_literal(value)}")
        lines.extend(["", "### Source presence and opaque extensions", "",
                      f"source_fields: {_literal(item['source_fields'])}",
                      f"source_extensions: {_literal(item['source_extensions'])}", ""])
        for key, heading in (("technical_history", "Technical history"), ("triage_history", "Triage history")):
            lines.extend([f"### {heading}", ""])
            if not item[key]:
                lines.extend(["No recorded events.", ""])
            for event in item[key]:
                lines.extend([f"#### Event {_literal(event['event_id'])}", ""])
                for field, value in sorted(event.items()):
                    lines.append(f"- {_literal(field)}: {_literal(value)}")
                lines.append("")
        if 'evidence' in item:
            lines.extend(['### Evidence', ''])
            if not item['evidence']:
                lines.extend(['No managed evidence associations.', ''])
            for evidence in item['evidence']:
                lines.extend([f"- {_literal(evidence)}", ''])
    content = "\n".join(lines).rstrip() + "\n"
    content.encode("utf-8")
    return content


def write_report(destination: Path, content: str, *, campaign: CampaignContext) -> None:
    """Publish a complete export exclusively; never overwrite assessment inputs."""
    destination = Path(destination)
    try:
        resolved = destination.resolve()
    except RuntimeError as error:
        # Python 3.12 translates ELOOP into this specific RuntimeError.
        if not str(error).startswith("Symlink loop from "):
            raise
        raise ValueError(f"Cannot resolve report output: symlink loop in {destination}") from error
    except OSError as error:
        if error.errno != errno.ELOOP:
            raise
        raise ValueError(f"Cannot resolve report output: symlink loop in {destination}") from error
    with directory_lock(campaign.findings_dir, create=False):
        entries = triage_journal.inspect_completed(campaign.findings_dir)
        protected = {campaign.data_dir.resolve(), campaign.evidence_dir.resolve()}
        protected.update((campaign.findings_dir / data["history_directory"]).resolve()
                         for _, data in entries)
        if (resolved.name.casefold().startswith(".aegis-lock.sqlite") or
                resolved in {campaign.config_file.resolve(), campaign.scope_file.resolve()} or
                any(resolved.is_relative_to(directory) for directory in protected)):
            raise ValueError("Report output must not modify assessment input paths")
        _publish(destination, content)


def _publish(destination, content):
    content.encode("utf-8")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Report destination already exists: {destination}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp",
                                             dir=destination.parent)
    try:
        try:
            stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic no-clobber publication, including a destination-creation race.
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)

"""Diagnostics that never render untrusted validation input or parser excerpts."""

from pydantic import ValidationError

# Unknown/extra mapping keys can themselves contain secrets. Only schema field
# names are safe to display; messages/context/input from validators are omitted.
_FIELDS = frozenset('schema_version evidence_id finding_id kind origin registered_at '
    'observed_at actor reason content_sha256 content_size representation source_integrity '
    'deduplication_key source_name result_filename result_sha256 result_id observation_id '
    'observation_index plugin plugin_version source_timestamp locator version timestamp '
    'status observations observation target type data coverage results filename sha256 '
    'baseline_type created_at verified_at max_object_bytes max_assessment_bytes'.split())

_DIAGNOSTICS = frozenset({
    'Evidence object size limit exceeded',
    'Observation index is outside the stored result',
    'Conflicting result integrity records',
    'Stored result differs from its integrity baseline',
    'Record identity or association key mismatch',
    'Evidence content digest or size mismatch',
    'Invalid observation snapshot structure',
    'Observation snapshot provenance contradicts association',
    'Duplicate observation snapshot member',
    'Nonfinite observation snapshot value',
})


def validation_summary(error):
    if isinstance(error, ValidationError):
        details = []
        for item in error.errors(include_input=False, include_context=False, include_url=False):
            location = '.'.join(str(part) if isinstance(part, int) or part in _FIELDS
                                else '<field>' for part in item['loc']) or '<record>'
            details.append(f"{location}: {item['type']}")
        return '; '.join(details)
    if type(error) is ValueError and str(error) in _DIAGNOSTICS:
        return str(error)
    return f'invalid data ({type(error).__name__})'

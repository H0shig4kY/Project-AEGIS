# Installation

## Requirements

Packaging declares Python **>=3.12** in [`aegis/pyproject.toml`](../aegis/pyproject.toml).
The tested CI matrix is Python **3.12 and 3.13**, on Linux and Windows. Do not infer
validation of newer Python versions from the lower-bound declaration.
Dependencies are installed by pip: Typer, Pydantic, PyYAML and Rich.

Clone or download the repository, then run these commands from its root (the
folder containing `README.md` and the `aegis/` subdirectory). Keep assessments
outside the source checkout. A local filesystem supporting hard links is needed
for evidence/report/package publication; Windows permissions require ACL review.

## Linux / POSIX

Use a suitable installed Python, for example `python3.12` if `python3` is older:

```bash
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./aegis
aegis --help
aegis version
```

## Windows PowerShell

With Python 3.12 installed and available through the Python launcher:

```powershell
py -3.12 --version
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ./aegis
aegis --help
aegis version
```

If local execution policy blocks activation, use the environment executables
directly; changing security policy is unnecessary:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ./aegis
.\.venv\Scripts\aegis.exe --help
```

## Windows CMD

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e ./aegis
aegis --help
aegis version
```

Use `py -3.13` instead if selecting installed Python 3.13. Double-quoted multiword
arguments work in POSIX, PowerShell and CMD; single quotes are not CMD quoting.
Single-line commands avoid incompatible shell continuation characters.

## Development and verification

For the suite, from the repository root:

```console
python -m pip install -e "./aegis[dev]"
cd aegis
python -m pytest -v
```

When already in `aegis/`, use `python -m pip install -e ".[dev]"`.
The [`tests` workflow](../.github/workflows/tests.yml) defines the CI matrix.
`aegis --help` lists current groups. `aegis commands` is useful but incomplete at
this baseline; use the [command reference](../aegis/COMMANDS.md).

## Troubleshooting

| Symptom | Check |
|---|---|
| `aegis` not found | Activate the environment or invoke its `aegis` executable directly. Confirm pip ran with that environment's Python. |
| Python requirement error | Check `python --version`; select 3.12/3.13 explicitly. |
| Packaging file not found | Repository root install path is `./aegis`, not `.`. |
| No assessment found | Enter the assessment created by `aegis init`; discovery searches ancestors for `aegis.yaml`. |
| Existing destination | Choose a new path; export/report commands do not silently overwrite. |
| Access, hard-link or integrity failure | Preserve data; see [recovery](recovery.md). Do not weaken permissions globally or delete evidence. |

Installing dependencies may require internet access. The [offline tutorial](quickstart.md)
itself does not run scans, but real `plugin run` operations may contact targets.

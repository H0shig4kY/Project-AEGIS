"""Cooperative local-file locks and complete-file publication, without domain migration."""

import json
import os
import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from functools import wraps
from pathlib import Path


class StorageIntegrityError(ValueError):
    """Existing storage is inconsistent; preserve it for inspection/recovery."""


_local = threading.local()


@contextmanager
def directory_lock(directory: Path, *, timeout: float = 10, create: bool = True):
    """Reentrant per-thread, cooperative per-process lock; yields whether nested.

    SQLite is only a lock provider. No domain records are stored in this database.
    A lock is released by SQLite/OS after process death; no stale lock deletion.
    create=False preserves missing directories/lock databases and refuses
    pre-existing sidecars instead of allowing implicit metadata recovery.
    """
    directory = Path(directory).resolve()
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    key = os.path.normcase(str(directory))
    # A fork inherits Python bookkeeping, not the parent's OS lock ownership.
    # Never reuse an inherited SQLite connection or claim child reentrancy.
    if getattr(_local, "pid", None) != os.getpid():
        _local.pid = os.getpid()
        _local.locks = {}
    held = getattr(_local, "locks", None)
    if held is None:
        held = _local.locks = {}
    if key in held:
        yield True
        return
    lock_path = directory / ".aegis-lock.sqlite"
    if not create:
        sidecars = [directory / (lock_path.name + suffix)
                    for suffix in ("-journal", "-wal", "-shm")]
        # Opening a hot SQLite journal can perform implicit recovery. Reporting
        # must preserve it instead, even if this conservatively rejects a busy
        # writer. Same-thread reentrancy above has already been handled.
        if any(path.exists() for path in sidecars):
            raise StorageIntegrityError(
                f"Busy or unsettled storage lock metadata for {directory}; "
                "retry after the writer exits or inspect/recover separately")
        if not lock_path.exists():
            # Legacy directories have no cooperative writer until its lock
            # appears. Never create operational files on the reporting path.
            try:
                yield False
            finally:
                if lock_path.exists() or any(path.exists() for path in sidecars):
                    raise StorageIntegrityError(
                        f"Storage changed during read-only snapshot: {directory}")
            return
    connection = None
    try:
        target = lock_path if create else lock_path.as_uri() + "?mode=rw"
        connection = sqlite3.connect(target, timeout=timeout,
                                     isolation_level=None, uri=not create)
        connection.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as error:
        if connection is not None:
            connection.close()
        raise StorageIntegrityError(f"Cannot acquire storage lock for {directory}: {error}") from error
    held[key] = connection
    try:
        yield False
    finally:
        del held[key]
        try:
            connection.rollback()
        finally:
            connection.close()


def locked_directory(attribute: str):
    """Serialize a store's internal read/modify/write method, preserving its API."""
    def decorate(function):
        @wraps(function)
        def wrapped(self, *args, **kwargs):
            with directory_lock(getattr(self, attribute)):
                return function(self, *args, **kwargs)
        return wrapped
    return decorate


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise StorageIntegrityError(f"Invalid JSON in {path}: {error}") from error


def sync_directory(directory: Path) -> None:
    # Windows has no portable directory-fsync equivalent in the stdlib.
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8",
                      exclusive: bool = False) -> None:
    """Publish a fully written sibling temp via replace, under a cooperative lock.

    Pre-publication failures retain the old target and the .tmp for inspection.
    After replace, a directory-sync error means publication is uncertain; callers
    must inspect/recover, never assume rollback. Raw noncooperating writers are
    outside this contract. Existing invalid JSON is never overwritten.
    """
    path = Path(path)
    with directory_lock(path.parent):
        if exclusive and path.exists():
            raise FileExistsError(path)
        if path.suffix in (".json", ".txn"):
            json.loads(content)
            if path.exists():
                read_json(path)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                                                 dir=path.parent)
        # Deliberately keep failed temp files; only the successful replacement
        # removes its own temp. Startup does not delete potential evidence.
        with os.fdopen(descriptor, "w", encoding=encoding) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)

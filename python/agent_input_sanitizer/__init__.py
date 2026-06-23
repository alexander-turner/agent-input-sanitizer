"""Python client for ``agent-input-sanitizer``.

The sanitization logic has a single source of truth: the JavaScript in
``src/``. This module is a thin client that shells out to the
``bin/sanitize-cli.mjs`` CLI, so a Python pipeline gets byte-identical verdicts
without a second implementation to keep in sync. It requires Node.js (>=20) on
``PATH``; there is deliberately no pure-Python fallback, because a port is
exactly the drift this design avoids.

Entry points:

* :func:`sanitize` — the one call most callers need. By default it pays the
  heavy ~200 ms HTML module-load only ONCE: the first ``html=True`` call spins
  up a shared, process-wide worker and every later ``html=True`` call reuses it
  (Layer-1-only calls stay one-shot, so a caller that never touches HTML never
  leaves a process running). Override with ``persist=True``/``False``.
* :class:`Sanitizer` — an explicitly-scoped long-lived worker, for callers that
  want to own the process lifetime via a context manager.
* :func:`shutdown_worker` — tear down the shared worker eagerly (it is also torn
  down at interpreter exit).
"""

import atexit
import json
import os
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

# The CLI lives at <repo>/bin/sanitize-cli.mjs; this module is at
# <repo>/python/agent_input_sanitizer/__init__.py, so the repo root is two
# parents up.
_CLI = Path(__file__).resolve().parents[2] / "bin" / "sanitize-cli.mjs"

__all__ = ["SanitizeResult", "sanitize", "Sanitizer", "shutdown_worker"]


@dataclass(frozen=True)
class SanitizeResult:
    """The :func:`sanitize` return shape, mirroring the JS API.

    ``cleaned`` is the sanitized text; ``found`` names the neutralized
    categories; ``warnings`` carries the operator-facing notices. As in JS, any
    change to the text comes with at least one warning.
    """

    cleaned: str
    found: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _node_missing(node: str) -> RuntimeError:
    return RuntimeError(
        f"Node.js (>=20) is required but {node!r} was not found on PATH. "
        "agent-input-sanitizer keeps a single JavaScript source of truth and "
        "has no pure-Python fallback; install Node to use the Python client."
    )


def _require_cli() -> None:
    """Fail with a clear message if the bundled CLI isn't where we expect.

    The CLI is resolved relative to this module's source tree, so the client
    only works from a repo checkout (it is not yet pip-installable). Without
    this check a missing CLI surfaces as an opaque "node: Cannot find module".
    """
    if not _CLI.is_file():
        raise RuntimeError(
            f"sanitize CLI not found at {_CLI}. The Python client resolves the "
            "bundled CLI relative to its source checkout and is not yet "
            "pip-installable; run it from a repo checkout."
        )


def _encode_request(text: str, html: bool) -> str:
    """The on-wire request envelope, single-sourced for both call paths."""
    return json.dumps({"text": text, "html": html})


def _parse_response(line: str) -> SanitizeResult:
    response = json.loads(line)
    if "error" in response:
        raise RuntimeError(f"sanitize CLI error: {response['error']}")
    return SanitizeResult(**response)


def sanitize(
    text: str,
    *,
    html: bool = False,
    persist: bool | None = None,
    node: str = "node",
) -> SanitizeResult:
    """Sanitize ``text``. Set ``html=True`` to also run the HTML layers.

    ``persist`` picks the process model (see the module docstring for the
    amortization rationale): ``None`` (default) routes through the shared worker
    exactly when ``html=True`` and stays one-shot otherwise; ``True``/``False``
    force the worker or a fresh one-shot subprocess. ``node`` overrides the
    executable, honored only when starting a fresh process.
    """
    _require_cli()
    if persist is None:
        persist = html
    if persist:
        with _shared_worker_lock:
            return _shared_worker(node).sanitize(text, html=html)

    try:
        proc = subprocess.run(
            [node, str(_CLI)],
            input=_encode_request(text, html),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except FileNotFoundError as cause:
        raise _node_missing(node) from cause
    if proc.returncode != 0:
        raise RuntimeError(
            f"sanitize CLI failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return _parse_response(proc.stdout)


class Sanitizer:
    """A long-lived sanitizer worker, for the hot path.

    Spawns one ``node ... --worker`` process and feeds it newline-delimited JSON
    requests, so the (heavy, when ``html=True``) module load is paid once rather
    than per call. Use as a context manager::

        with Sanitizer() as s:
            for page in pages:
                result = s.sanitize(page, html=True)
    """

    def __init__(self, node: str = "node") -> None:
        self._node = node
        self._proc: subprocess.Popen | None = None
        # The pid that spawned the worker, so a worker inherited across os.fork
        # can be detected and not shared between processes (see _shared_worker).
        self._pid: int | None = None
        # Worker stderr goes to a temp file, never a pipe: nobody drains stderr
        # between requests, so a pipe could fill (Node warnings, etc.) and block
        # the worker mid-response, deadlocking the readline below. A file never
        # blocks, and we still read it back for diagnostics if the worker dies.
        self._stderr: tempfile.SpooledTemporaryFile | None = None

    def start(self) -> "Sanitizer":
        _require_cli()
        self._pid = os.getpid()
        self._stderr = tempfile.SpooledTemporaryFile(mode="w+", encoding="utf-8")
        try:
            self._proc = subprocess.Popen(
                [self._node, str(_CLI), "--worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except FileNotFoundError as cause:
            self._stderr.close()
            self._stderr = None
            raise _node_missing(self._node) from cause
        return self

    def __enter__(self) -> "Sanitizer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def sanitize(self, text: str, *, html: bool = False) -> SanitizeResult:
        if self._proc is None or self._proc.poll() is not None:
            raise RuntimeError("worker is not running (use it as a context manager)")
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(_encode_request(text, html) + "\n")
        self._proc.stdin.flush()
        # Blocking read with no timeout, under _shared_worker_lock for the shared
        # worker: the serialized one-line-per-request protocol can't interleave,
        # but a worker that never answers would wedge every persistent caller.
        # The CLI emits exactly one line per request, so this is bounded in
        # practice; a hang means a CLI bug, surfaced as a stuck process.
        line = self._proc.stdout.readline()
        if line == "":
            raise RuntimeError(
                f"sanitize worker exited unexpectedly: {self._drain_stderr()}"
            )
        return _parse_response(line)

    def _drain_stderr(self) -> str:
        if self._stderr is None:
            return ""
        self._stderr.seek(0)
        return self._stderr.read().strip()

    def close(self) -> None:
        if self._proc is None:
            return
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        self._proc = None
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None


# Process-wide worker backing the persistent path of `sanitize`. The lock is
# held across each full request/response so concurrent persistent callers can't
# interleave writes and reads on the one shared pipe (which would desync the
# protocol); it also guards spin-up and teardown of `_worker` itself.
_worker: Sanitizer | None = None
_shared_worker_lock = threading.Lock()
_atexit_registered = False


def _shared_worker(node: str) -> Sanitizer:
    """Return the shared worker, starting it on first use. Caller holds the lock.

    Two cases force a fresh worker:

    * Inherited across ``os.fork`` (pid mismatch) — the Popen and its pipes
      belong to the parent; two processes driving one pipe would desync the
      protocol. Abandon the reference WITHOUT ``close()`` (reaping a process this
      child doesn't own is undefined) and spawn one this process owns.
    * Dead (its prior request already raised, surfacing the failure loudly) —
      reap its pipes/temp file, then replace it, so the path self-heals instead
      of wedging every later call on a corpse.
    """
    global _worker, _atexit_registered
    if _worker is not None:
        if _worker._pid != os.getpid():
            _worker = None  # inherited across fork; do not reap the parent's proc
        elif not _worker.is_alive():
            _worker.close()
            _worker = None
    if _worker is None:
        _worker = Sanitizer(node=node).start()
        if not _atexit_registered:
            atexit.register(shutdown_worker)
            _atexit_registered = True
    return _worker


def shutdown_worker() -> None:
    """Tear down the shared persistent worker if one is running. Idempotent."""
    global _worker
    with _shared_worker_lock:
        if _worker is None:
            return
        _worker.close()
        _worker = None

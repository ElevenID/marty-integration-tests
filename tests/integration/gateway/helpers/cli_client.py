"""Wrapper around the Marty CLI (Node.js) for integration testing.

Runs CLI commands as subprocesses, configuring auth and organization via
temporary config files.  Parses JSON output when available, otherwise
returns raw text.

Usage in tests::

    @pytest.fixture
    async def cli_client(test_session_id):
        async with MartyCLIClient(session_id=test_session_id) as cli:
            yield cli

    async def test_health(cli_client):
        result = cli_client.run("health")
        assert result.returncode == 0
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# CLI binary — resolved once at import time
_WORKSPACE_ROOT = Path(__file__).resolve().parents[5]  # .../work/
_CLI_DIR = Path(
    os.environ.get("MARTY_CLI_DIR", str(_WORKSPACE_ROOT / "marty-ui" / "cli"))
)
_CLI_BIN = _CLI_DIR / "bin" / "marty.js"


class CLIResult:
    """Result of a CLI command execution."""

    __slots__ = ("returncode", "stdout", "stderr", "command")

    def __init__(
        self, returncode: int, stdout: str, stderr: str, command: list[str]
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.command = command

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def json(self) -> Any:
        """Parse stdout as JSON.  Raises ValueError on failure."""
        return json.loads(self.stdout)

    def json_or_none(self) -> Any | None:
        """Parse stdout as JSON, returning None if it fails."""
        try:
            return json.loads(self.stdout)
        except (json.JSONDecodeError, ValueError):
            return None

    def __repr__(self) -> str:
        cmd_str = " ".join(self.command[-4:])
        return f"<CLIResult rc={self.returncode} cmd=...{cmd_str}>"


class MartyCLIClient:
    """Integration-test wrapper around the ``marty`` Node.js CLI.

    Manages a temporary ``~/.marty`` config directory so tests don't touch
    the developer's real CLI credentials.

    Parameters
    ----------
    session_id:
        A valid gateway ``sessionId`` cookie value (from the PKCE auth flow).
    gateway_url:
        Gateway base URL.  Defaults to ``GATEWAY_URL`` env or ``http://localhost:8000``.
    organization_id:
        Default org to use for commands that require one.
    """

    def __init__(
        self,
        session_id: str,
        gateway_url: str | None = None,
        organization_id: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.gateway_url = gateway_url or os.getenv(
            "GATEWAY_URL", "http://localhost:8000"
        )
        self.organization_id = organization_id
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._config_dir: Path | None = None

    # -- context manager ---------------------------------------------------

    async def __aenter__(self) -> MartyCLIClient:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="marty-cli-test-")
        self._config_dir = Path(self._tmpdir.name) / ".marty"
        self._config_dir.mkdir()
        self._write_config()
        self._write_credentials()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._tmpdir:
            self._tmpdir.cleanup()
            self._tmpdir = None

    def set_organization(self, org_id: str) -> None:
        """Switch the active organization and rewrite config."""
        self.organization_id = org_id
        self._write_config()

    # -- internal ----------------------------------------------------------

    def _write_config(self) -> None:
        assert self._config_dir
        cfg: Dict[str, Any] = {"apiUrl": self.gateway_url}
        if self.organization_id:
            cfg["organizationId"] = self.organization_id
        (self._config_dir / "config.json").write_text(json.dumps(cfg, indent=2))

    def _write_credentials(self) -> None:
        assert self._config_dir
        creds = {
            "type": "session",
            "sessionId": self.session_id,
        }
        cred_path = self._config_dir / "credentials.json"
        cred_path.write_text(json.dumps(creds))
        cred_path.chmod(0o600)

    def _env(self) -> Dict[str, str]:
        """Build the subprocess environment with HOME overridden."""
        env = os.environ.copy()
        # Override HOME so the CLI reads from our temp config dir
        assert self._tmpdir
        env["HOME"] = self._tmpdir.name
        env["MARTY_API_URL"] = self.gateway_url
        if self.organization_id:
            env["MARTY_ORG_ID"] = self.organization_id
        return env

    # -- public API --------------------------------------------------------

    def run(
        self,
        *args: str,
        timeout: int = 30,
        json_output: bool = False,
    ) -> CLIResult:
        """Run a CLI command and return the result.

        Parameters
        ----------
        *args:
            CLI arguments, e.g. ``"orgs", "list"`` for ``marty orgs list``.
        timeout:
            Subprocess timeout in seconds.
        json_output:
            If True, appends ``-o json`` to the command.
        """
        cmd = ["node", str(_CLI_BIN)] + list(args)
        if json_output:
            cmd.extend(["-o", "json"])

        logger.debug("CLI> %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._env(),
                cwd=str(_CLI_DIR),
            )
        except subprocess.TimeoutExpired as exc:
            return CLIResult(
                returncode=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                command=cmd,
            )

        result = CLIResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            command=cmd,
        )
        logger.debug(
            "CLI< rc=%d stdout=%d bytes stderr=%d bytes",
            result.returncode,
            len(result.stdout),
            len(result.stderr),
        )
        return result

    # -- convenience wrappers ----------------------------------------------

    def health(self) -> CLIResult:
        """``marty health``"""
        return self.run("health")

    def orgs_list(self) -> CLIResult:
        """``marty orgs list -o json``"""
        return self.run("orgs", "list", json_output=True)

    def templates_list(self) -> CLIResult:
        """``marty templates list -o json``"""
        return self.run("templates", "list", json_output=True)

    def credentials_list(self) -> CLIResult:
        """``marty credentials list -o json``"""
        return self.run("credentials", "list", json_output=True)

    def verify_start(self, policy_id: str) -> CLIResult:
        """``marty verify start --policy <id> -o json``"""
        return self.run("verify", "start", "--policy", policy_id, json_output=True)

    def verify_status(self, session_id: str) -> CLIResult:
        """``marty verify status <id> -o json``"""
        return self.run("verify", "status", session_id, json_output=True)

    def verify_sessions(self) -> CLIResult:
        """``marty verify sessions -o json``"""
        return self.run("verify", "sessions", json_output=True)

    def test_e2e(
        self,
        scenario: str = "health",
        credential_config: str | None = None,
        policy: str | None = None,
    ) -> CLIResult:
        """``marty test e2e --scenario <name>``"""
        args = ["test", "e2e", "--scenario", scenario]
        if credential_config:
            args.extend(["--credential-config", credential_config])
        if policy:
            args.extend(["--policy", policy])
        return self.run(*args)

    def flows_list(self) -> CLIResult:
        """``marty flows list -o json``"""
        return self.run("flows", "list", json_output=True)

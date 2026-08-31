# Installation

trustrail requires Python 3.11 or newer.

=== "pip"

    ```bash
    python -m pip install trustrail
    ```

=== "uv"

    ```bash
    uv add trustrail
    ```

=== "Poetry"

    ```bash
    poetry add trustrail
    ```

## Optional integrations

Install only the adapters your application needs:

```bash
python -m pip install "trustrail[openai]"
python -m pip install "trustrail[fastapi]"
python -m pip install "trustrail[langchain]"
python -m pip install "trustrail[llamaindex]"
python -m pip install "trustrail[redis,otel]"
```

The base package imports without Redis installed. Install the `redis` extra only
when constructing `RedisStateBackend`; otherwise `from_url()` raises an
actionable optional-dependency error. Redis connection URLs support authenticated
`redis://` connections and TLS-protected `rediss://` connections. Keep credentials
in your deployment secret store rather than source code or command history.

For local development, clone the repository and install the development group:

```bash
git clone https://github.com/hasansajedi/trustrail.git
cd trustrail
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
```

## Verify the installation

```bash
python -c "import trustrail; print(trustrail.__version__)"
trustrail --version
```

Both commands should print the same installed version. Continue with the
[quick start](quickstart.md).

!!! note
    trustrail is an application-layer control. Keep provider moderation,
    authorization, sandboxing, rate limits, and output encoding enabled.

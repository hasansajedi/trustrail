# Installation

aiRail requires Python 3.11 or newer.

=== "pip"

    ```bash
    python -m pip install aiRail
    ```

=== "uv"

    ```bash
    uv add aiRail
    ```

=== "Poetry"

    ```bash
    poetry add aiRail
    ```

## Optional integrations

Install only the adapters your application needs:

```bash
python -m pip install "aiRail[openai]"
python -m pip install "aiRail[fastapi]"
python -m pip install "aiRail[langchain]"
python -m pip install "aiRail[llamaindex]"
python -m pip install "aiRail[redis,otel]"
```

For local development, clone the repository and install the development group:

```bash
git clone https://github.com/hasansajedi/aiRail.git
cd aiRail
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
```

## Verify the installation

```bash
python -c "import aiRail; print(aiRail.__version__)"
aiRail --version
```

Both commands should print the same installed version. Continue with the
[quick start](quickstart.md).

!!! note
    aiRail is an application-layer control. Keep provider moderation,
    authorization, sandboxing, rate limits, and output encoding enabled.

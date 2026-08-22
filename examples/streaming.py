"""Streaming content scanner example."""

import asyncio

from trustrail import Guard, GuardStage


async def simulate_stream():
    """Simulate an LLM response stream."""
    chunks = [
        "Here is some information about Python: ",
        "Python is a high-level programming language. ",
        "It supports multiple programming paradigms. ",
        "Visit https://docs.python.org for more info.",
    ]
    for chunk in chunks:
        yield chunk
        await asyncio.sleep(0.1)


async def main() -> None:
    guard = Guard.balanced()
    scanner = guard.stream(GuardStage.STREAM)

    print("Scanning stream chunks:\n")
    async for result in scanner.scan(simulate_stream()):
        status = "BLOCKED" if result.is_blocked else "OK"
        print(f"[{status}] Chunk: {result.chunk!r}")
        if result.findings:
            for f in result.findings:
                print(f"         Finding: {f.message}")

    final = scanner.finalize()
    print(f"\nFinal result: {final.action.value}, score={final.score.value}")


if __name__ == "__main__":
    asyncio.run(main())

"""Guard fully bound function arguments and forward their safe values."""

from trustrail import Guard, GuardConfig, GuardrailBlockedError, SensitiveDataMode

guard = Guard(
    GuardConfig(
        sensitive_data_mode=SensitiveDataMode.REDACT,
        audit_enabled=False,
    )
)


@guard.input(selector="message")
def enqueue_message(user_id: str, *, message: str = "Contact default@example.com") -> str:
    """Represent an application function called only with transformed input."""
    return f"{user_id}: {message}"


@guard.tool()
def search_documents(query: str, *, limit: int = 5) -> str:
    """Represent a tool whose complete bound call is checked before execution."""
    return f"search={query!r}, limit={limit}"


print(enqueue_message("authenticated-user"))
print(search_documents("quarterly report", limit=3))

try:
    search_documents("; rm -rf /important")
except GuardrailBlockedError:
    print("Unsafe tool arguments were blocked before the function ran")

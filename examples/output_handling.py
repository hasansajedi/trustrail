"""Validate model output, then apply a contract for the destination sink."""

from pydantic import BaseModel, ConfigDict

from trustrail import (
    Guard,
    GuardStage,
    OutputContext,
    OutputHandlingError,
    OutputHandlingPolicy,
    SafeOutputHandler,
)


class SearchResult(BaseModel):
    """Strict application-owned schema for structured model output."""

    model_config = ConfigDict(extra="forbid")

    title: str
    document_ids: list[int]


guard = Guard.silent()
handler = SafeOutputHandler(
    OutputHandlingPolicy(allowed_url_hosts=frozenset({"docs.example.test"}))
)

model_text = "Use <strong>care</strong> when rotating credentials."
checked_text = guard.protect(model_text, GuardStage.FINAL_OUTPUT)
safe_html_text = handler.require(checked_text, OutputContext.HTML)
print(safe_html_text)

model_json = '{"title":"Quarterly report","document_ids":[1,2,3]}'
checked_json = guard.protect(model_json, GuardStage.LLM_RESPONSE)
structured = handler.parse_json(checked_json, SearchResult)
print(structured)

safe_url = handler.require("https://docs.example.test/guide", OutputContext.URL)
print(safe_url)

try:
    handler.require("http://169.254.169.254/latest/meta-data", OutputContext.URL)
except OutputHandlingError:
    print("Unsafe URL was rejected before the network boundary")

model_title = "Robert'); DROP TABLE contacts;--"
sql_parameter = handler.as_sql_parameter(model_title)
print("Bind as data: database.execute(query, (sql_parameter,))")
assert sql_parameter == model_title

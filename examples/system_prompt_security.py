"""Validate a system prompt and block prompt fragments in generated output."""

from trustrail import (
    SystemPromptDataClass,
    SystemPromptLeakageDetector,
    SystemPromptReference,
    SystemPromptTemplate,
    SystemPromptValidator,
    SystemPromptVariable,
)

validated = SystemPromptValidator().require(
    SystemPromptTemplate(
        template_id="support-v1",
        template=(
            "You are a {{tone}} support assistant. Answer using reviewed public documentation only."
        ),
        variables=(
            SystemPromptVariable(
                name="tone",
                value="concise",
                data_class=SystemPromptDataClass.BEHAVIOR,
            ),
        ),
    )
)

# Send validated.content to the model provider as the system message.
model_output = "The public documentation is available in the support center."

reference = SystemPromptReference.from_validated(validated)
SystemPromptLeakageDetector().require_safe(model_output, [reference])
print(model_output)

"""Output safety policy."""

from __future__ import annotations

from trustrail.policies.base import BasePolicy
from trustrail.rules.base import BaseRule
from trustrail.rules.output import (
    DangerousCodeConstructRule,
    FilePathInjectionRule,
    HtmlInjectionRule,
    LdapInjectionRule,
    LogInjectionRule,
    MarkdownExternalImageRule,
    PathTraversalRule,
    ShellMetacharRule,
    SqlInjectionRule,
    SstiDetectionRule,
    SuspiciousUrlRule,
    UnsafeProtocolRule,
    XmlXpathInjectionRule,
)
from trustrail.rules.url import (
    EmbeddedCredentialRule,
    MetadataServiceRule,
    PrivateIpRule,
    SchemeValidationRule,
)


class OutputSafetyPolicy(BasePolicy):
    """Policy for validating LLM output safety."""

    def __init__(
        self,
        enabled: bool = True,
        include_xss: bool = True,
        include_path_traversal: bool = True,
        include_shell: bool = True,
        include_url_checks: bool = True,
        include_markdown: bool = True,
        include_code_injection: bool = True,
        include_sql_injection: bool = True,
        include_ssti: bool = True,
        include_log_injection: bool = True,
        include_ldap_injection: bool = True,
        include_xml_xpath: bool = True,
        include_file_path: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.include_xss = include_xss
        self.include_path_traversal = include_path_traversal
        self.include_shell = include_shell
        self.include_url_checks = include_url_checks
        self.include_markdown = include_markdown
        self.include_code_injection = include_code_injection
        self.include_sql_injection = include_sql_injection
        self.include_ssti = include_ssti
        self.include_log_injection = include_log_injection
        self.include_ldap_injection = include_ldap_injection
        self.include_xml_xpath = include_xml_xpath
        self.include_file_path = include_file_path

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = []

        if self.include_xss:
            rules.append(HtmlInjectionRule())

        if self.include_path_traversal:
            rules.append(PathTraversalRule())

        if self.include_shell:
            rules.append(ShellMetacharRule())

        if self.include_code_injection:
            rules.append(DangerousCodeConstructRule())

        if self.include_sql_injection:
            rules.append(SqlInjectionRule())

        if self.include_ssti:
            rules.append(SstiDetectionRule())

        if self.include_log_injection:
            rules.append(LogInjectionRule())

        if self.include_ldap_injection:
            rules.append(LdapInjectionRule())

        if self.include_xml_xpath:
            rules.append(XmlXpathInjectionRule())

        if self.include_file_path:
            rules.append(FilePathInjectionRule())

        if self.include_url_checks:
            rules.extend(
                [
                    UnsafeProtocolRule(),
                    SuspiciousUrlRule(),
                    SchemeValidationRule(),
                    PrivateIpRule(),
                    MetadataServiceRule(),
                    EmbeddedCredentialRule(),
                ]
            )

        if self.include_markdown:
            rules.append(MarkdownExternalImageRule())

        return rules + self._rules

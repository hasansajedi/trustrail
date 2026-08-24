"""Sensitive data detection policy."""

from __future__ import annotations

from trustrail.policies.base import BasePolicy
from trustrail.rules.base import BaseRule
from trustrail.rules.sensitive_data import (
    AwsKeyRule,
    BearerTokenRule,
    DatabaseUrlRule,
    DriversLicenseRule,
    EmailRule,
    HighEntropySecretRule,
    IbanRule,
    IpAddressRule,
    JwtTokenRule,
    NamedCredentialRule,
    PassportNumberRule,
    PaymentCardRule,
    PhoneRule,
    PrivateKeyRule,
    ProviderApiTokenRule,
    SsnRule,
)


class SensitiveDataPolicy(BasePolicy):
    """Policy for detecting and redacting sensitive data."""

    def __init__(
        self,
        enabled: bool = True,
        include_pii: bool = True,
        include_extended_pii: bool = True,
        include_secrets: bool = True,
        include_payment: bool = True,
        include_ip: bool = False,  # Low severity, off by default
    ) -> None:
        super().__init__(enabled=enabled)
        self.include_pii = include_pii
        self.include_extended_pii = include_extended_pii
        self.include_secrets = include_secrets
        self.include_payment = include_payment
        self.include_ip = include_ip

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = []

        if self.include_pii:
            rules.extend([EmailRule(), PhoneRule()])

        if self.include_extended_pii:
            rules.extend([SsnRule(), IbanRule(), PassportNumberRule(), DriversLicenseRule()])

        if self.include_ip:
            rules.append(IpAddressRule())

        if self.include_payment:
            rules.append(PaymentCardRule())

        if self.include_secrets:
            rules.extend(
                [
                    JwtTokenRule(),
                    BearerTokenRule(),
                    AwsKeyRule(),
                    PrivateKeyRule(),
                    DatabaseUrlRule(),
                    NamedCredentialRule(),
                    HighEntropySecretRule(),
                    ProviderApiTokenRule(),
                ]
            )

        return rules + self._rules

"""
Organization authorization integration tests.

.. deprecated::
    These tests used placeholder session cookies and hardcoded org UUIDs and
    could never pass against a live environment.

    They have been rewritten as properly-authenticated tests at::

        tests/integration/gateway/test_org_authorization.py

    which use the Keycloak PKCE flow, the GatewayClient fixture, and random
    org UUIDs to test cross-org middleware enforcement without a second user.

This module is retained to avoid breaking pytest collection but all
classes are skipped.
"""

import pytest


_REDIRECT = (
    "Superseded by tests/integration/gateway/test_org_authorization.py "
    "which uses real Keycloak auth and per-test org fixtures."
)


@pytest.mark.skip(reason=_REDIRECT)
class TestOrganizationMembershipEnforcement:
    async def test_non_member_cannot_access_org_details(self): pass
    async def test_member_can_access_org_details(self): pass
    async def test_member_cannot_invite_others(self): pass
    async def test_admin_can_invite_members(self): pass


@pytest.mark.skip(reason=_REDIRECT)
class TestCrossOrganizationAttacks:
    async def test_cannot_invite_to_other_org(self): pass
    async def test_cannot_create_api_keys_for_other_org(self): pass
    async def test_cannot_access_other_org_members(self): pass
    async def test_cannot_create_credential_template_in_other_org(self): pass


@pytest.mark.skip(reason=_REDIRECT)
class TestCacheInvalidation:
    async def test_cache_invalidated_after_role_change(self): pass
    async def test_cache_invalidated_after_removal(self): pass


@pytest.mark.skip(reason="Requires full test environment setup")
class TestEndToEndFlows:
    async def test_full_cross_org_attack_scenario(self): pass

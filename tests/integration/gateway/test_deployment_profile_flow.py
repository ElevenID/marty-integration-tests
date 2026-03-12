"""
Deployment Profile Flow Integration Tests

Tests deployment profile and lane management:
1. Deployment Profile CRUD operations
2. Deployment Profile activation lifecycle
3. Lane management (CRUD, device assignment)
4. Deployment Profile + Presentation Policy integration
5. API key generation for deployment profiles

Deployment profiles package trust + policies + runtime behavior for real endpoints.
They contain lanes (logical device groupings) that can have policy overrides.
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestDeploymentProfileCRUD:
    """Test deployment profile CRUD operations"""
    
    async def test_create_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test creating a deployment profile"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
            name="Airport Security Gate",
            default_presentation_policy_id=age_verification_policy["id"],
        )
        
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        assert profile is not None
        assert "id" in profile
        assert profile["organization_id"] == test_organization["id"]
        assert profile["name"] == "Airport Security Gate"
        assert profile["network_mode"] == "online"
        assert profile["default_presentation_policy_id"] == age_verification_policy["id"]
        
    async def test_get_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Test retrieving a deployment profile by ID"""
        profile_id = test_deployment_profile["id"]
        
        profile = await gateway_client.get_deployment_profile(profile_id)
        
        assert profile["id"] == profile_id
        assert profile["name"] == test_deployment_profile["name"]
        
    async def test_list_deployment_profiles(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_deployment_profile: Dict[str, Any],
    ):
        """Test listing deployment profiles for an organization"""
        profiles = await gateway_client.list_deployment_profiles(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(profiles, list)
        assert len(profiles) > 0
        
        profile_ids = [p["id"] for p in profiles]
        assert test_deployment_profile["id"] in profile_ids
        
    async def test_update_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Test updating a deployment profile"""
        profile_id = test_deployment_profile["id"]
        
        updated = await gateway_client.update_deployment_profile(
            profile_id=profile_id,
            name="Updated Gate Name",
            network_mode="offline",
            biometric_required=True,
        )
        
        assert updated["id"] == profile_id
        assert updated["name"] == "Updated Gate Name"
        assert updated["network_mode"] == "offline"
        assert updated["biometric_required"] is True
        
    async def test_delete_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deleting a deployment profile"""
        # Create a profile to delete
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
            name="Profile to Delete",
        )
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        # Delete it
        await gateway_client.delete_deployment_profile(profile["id"])
        
        # Verify it's gone
        profiles = await gateway_client.list_deployment_profiles(
            organization_id=test_organization["id"]
        )
        profile_ids = [p["id"] for p in profiles]
        assert profile["id"] not in profile_ids


@pytest.mark.asyncio
@pytest.mark.integration
class TestDeploymentProfileActivation:
    """Test deployment profile activation lifecycle"""
    
    async def test_activate_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Test activating a deployment profile"""
        profile_id = test_deployment_profile["id"]
        
        activated = await gateway_client.activate_deployment_profile(profile_id)
        
        assert activated["id"] == profile_id
        assert activated["status"] in ["active", "activated"]
        
    async def test_deployment_profile_status_transitions(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deployment profile status transitions"""
        # Create profile (should start as draft/inactive)
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
        )
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        # Initial status should be draft or inactive
        assert profile["status"] in ["draft", "inactive", "created"]
        
        # Activate it
        activated = await gateway_client.activate_deployment_profile(profile["id"])
        assert activated["status"] in ["active", "activated"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestLaneManagement:
    """Test lane CRUD and management"""
    
    async def test_create_lane(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Test creating a lane within a deployment profile"""
        lane_data = TestDataBuilder.lane(
            deployment_profile_id=test_deployment_profile["id"],
            name="Gate 12A",
            location="Terminal 2, Concourse A",
            device_type="gate",
        )
        
        lane = await gateway_client.create_lane(
            profile_id=test_deployment_profile["id"],
            **lane_data,
        )
        
        assert lane is not None
        assert "id" in lane
        assert lane["name"] == "Gate 12A"
        assert lane["location"] == "Terminal 2, Concourse A"
        assert lane["device_type"] == "gate"
        
    async def test_get_lane(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
        test_lane: Dict[str, Any],
    ):
        """Test retrieving a lane by ID"""
        lane = await gateway_client.get_lane(
            profile_id=test_deployment_profile["id"],
            lane_id=test_lane["id"],
        )
        
        assert lane["id"] == test_lane["id"]
        assert lane["name"] == test_lane["name"]
        
    async def test_list_lanes(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
        test_lane: Dict[str, Any],
    ):
        """Test listing lanes for a deployment profile"""
        lanes = await gateway_client.list_lanes(
            profile_id=test_deployment_profile["id"]
        )
        
        assert isinstance(lanes, list)
        assert len(lanes) > 0
        
        lane_ids = [l["id"] for l in lanes]
        assert test_lane["id"] in lane_ids
        
    async def test_update_lane(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
        test_lane: Dict[str, Any],
    ):
        """Test updating a lane"""
        updated = await gateway_client.update_lane(
            profile_id=test_deployment_profile["id"],
            lane_id=test_lane["id"],
            name="Updated Lane Name",
            location="New Location",
        )
        
        assert updated["id"] == test_lane["id"]
        assert updated["name"] == "Updated Lane Name"
        assert updated["location"] == "New Location"
        
    async def test_delete_lane(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Test deleting a lane"""
        # Create a lane to delete
        lane_data = TestDataBuilder.lane(
            deployment_profile_id=test_deployment_profile["id"],
            name="Lane to Delete",
        )
        lane = await gateway_client.create_lane(
            profile_id=test_deployment_profile["id"],
            **lane_data,
        )
        
        # Delete it
        await gateway_client.delete_lane(
            profile_id=test_deployment_profile["id"],
            lane_id=lane["id"],
        )
        
        # Verify it's gone
        lanes = await gateway_client.list_lanes(
            profile_id=test_deployment_profile["id"]
        )
        lane_ids = [l["id"] for l in lanes]
        assert lane["id"] not in lane_ids
        
    async def test_create_multiple_lanes(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Test creating multiple lanes in a deployment profile"""
        lane_names = ["Gate 1", "Gate 2", "Gate 3"]
        created_lanes = []
        
        for name in lane_names:
            lane_data = TestDataBuilder.lane(
                deployment_profile_id=test_deployment_profile["id"],
                name=name,
            )
            lane = await gateway_client.create_lane(
                profile_id=test_deployment_profile["id"],
                **lane_data,
            )
            created_lanes.append(lane)
        
        # List all lanes
        all_lanes = await gateway_client.list_lanes(
            profile_id=test_deployment_profile["id"]
        )
        
        # All created lanes should be in the list
        created_ids = {l["id"] for l in created_lanes}
        listed_ids = {l["id"] for l in all_lanes}
        
        assert created_ids.issubset(listed_ids)


@pytest.mark.asyncio
@pytest.mark.integration
class TestDeviceAssignment:
    """Test device assignment to lanes"""
    
    async def test_assign_device_to_lane(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
        test_lane: Dict[str, Any],
    ):
        """Test assigning a device to a lane"""
        device_id = "device-001"
        device_name = "Kiosk Terminal 12A"
        
        result = await gateway_client.assign_device_to_lane(
            profile_id=test_deployment_profile["id"],
            lane_id=test_lane["id"],
            device_id=device_id,
            device_name=device_name,
        )
        
        assert result is not None
        # Result could be the updated lane or an assignment record
        # Verify the assignment was successful
        assert "id" in result or "device_id" in result
        
    async def test_assign_multiple_devices_to_lane(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
        test_lane: Dict[str, Any],
    ):
        """Test assigning multiple devices to the same lane"""
        devices = [
            ("device-101", "Kiosk A"),
            ("device-102", "Kiosk B"),
            ("device-103", "Kiosk C"),
        ]
        
        for device_id, device_name in devices:
            result = await gateway_client.assign_device_to_lane(
                profile_id=test_deployment_profile["id"],
                lane_id=test_lane["id"],
                device_id=device_id,
                device_name=device_name,
            )
            assert result is not None
            
        # Get updated lane info
        lane = await gateway_client.get_lane(
            profile_id=test_deployment_profile["id"],
            lane_id=test_lane["id"],
        )
        
        # Lane should reflect device count
        assert lane.get("device_count", 0) >= len(devices)


@pytest.mark.asyncio
@pytest.mark.integration
class TestDeploymentProfileWithPolicy:
    """Test deployment profile integration with presentation policies"""
    
    async def test_deployment_profile_with_default_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test deployment profile with default presentation policy"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
            default_presentation_policy_id=age_verification_policy["id"],
        )
        
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        assert profile["default_presentation_policy_id"] == age_verification_policy["id"]
        
    async def test_update_default_policy(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
        identity_verification_policy: Dict[str, Any],
    ):
        """Test updating the default presentation policy"""
        updated = await gateway_client.update_deployment_profile(
            profile_id=test_deployment_profile["id"],
            default_presentation_policy_id=identity_verification_policy["id"],
        )
        
        assert updated["default_presentation_policy_id"] == identity_verification_policy["id"]
        
    async def test_deployment_profile_verification_flow(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test starting a verification flow using a deployment profile's policy"""
        # The deployment profile has a default policy
        # Start a verification flow using that policy
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        assert flow is not None
        assert "instance_id" in flow
        assert "request_uri" in flow or "qr_code_data" in flow


@pytest.mark.asyncio
@pytest.mark.integration
class TestDeploymentProfileAPIKey:
    """Test API key generation for deployment profiles"""
    
    async def test_generate_deployment_profile_api_key(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Test generating an API key for a deployment profile"""
        result = await gateway_client.generate_deployment_profile_api_key(
            test_deployment_profile["id"]
        )
        
        assert result is not None
        assert "api_key" in result or "key" in result or "api_key_id" in result
        
        # API key should be returned (only shown once)
        if "api_key" in result:
            assert len(result["api_key"]) > 20  # Should be a long random string
        elif "key" in result:
            assert len(result["key"]) > 20


@pytest.mark.asyncio
@pytest.mark.integration
class TestDeploymentProfileErrors:
    """Test error handling for deployment profiles"""
    
    async def test_create_profile_invalid_organization(
        self,
        gateway_client: GatewayClient,
    ):
        """Test creating deployment profile with invalid organization ID"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id="invalid-org-id-999",
        )
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_deployment_profile(**profile_data)
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()
        
    async def test_get_nonexistent_profile(
        self,
        gateway_client: GatewayClient,
    ):
        """Test getting a non-existent deployment profile"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.get_deployment_profile("nonexistent-profile-id")
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()
        
    async def test_create_lane_invalid_profile(
        self,
        gateway_client: GatewayClient,
    ):
        """Test creating lane with invalid profile ID"""
        lane_data = TestDataBuilder.lane(
            deployment_profile_id="invalid-profile-id",
        )
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_lane(
                profile_id="invalid-profile-id",
                **lane_data,
            )
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()
        
    async def test_delete_active_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deleting an active profile (should fail or deactivate first)"""
        # Create and activate a profile
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
        )
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        # Activate it
        await gateway_client.activate_deployment_profile(profile["id"])
        
        # Try to delete it (behavior depends on implementation)
        # Either it should fail, or automatically deactivate first
        try:
            await gateway_client.delete_deployment_profile(profile["id"])
            # If deletion succeeds, that's also valid (deactivate + delete)
        except Exception as e:
            # If it fails, should be a clear error about active status
            error_msg = str(e).lower()
            assert "active" in error_msg or "status" in error_msg


@pytest.mark.asyncio
@pytest.mark.integration
class TestDeploymentProfileConfiguration:
    """Test deployment profile configuration options"""
    
    async def test_offline_mode_configuration(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deployment profile with offline mode configuration"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
        )
        profile_data["network_mode"] = "offline"
        profile_data["offline_cache_ttl_hours"] = 48
        
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        assert profile["network_mode"] == "offline"
        assert profile["offline_cache_ttl_hours"] == 48
        
    async def test_biometric_configuration(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deployment profile with biometric requirements"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
        )
        profile_data["biometric_required"] = True
        
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        assert profile["biometric_required"] is True
        
    async def test_ux_configuration(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deployment profile UX configuration"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
        )
        profile_data["ux_config"] = {
            "language": "es",
            "signage_text": "Por favor escanee su credencial",
            "operator_mode": True,
            "accessibility": True,
            "theme": "dark",
        }
        
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        assert profile["ux_config"]["language"] == "es"
        assert profile["ux_config"]["operator_mode"] is True
        
    async def test_audit_configuration(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deployment profile audit configuration"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
        )
        profile_data["audit_all_events"] = True
        
        profile = await gateway_client.create_deployment_profile(**profile_data)
        
        assert profile["audit_all_events"] is True

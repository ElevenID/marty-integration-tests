/*
 * Request/response data classes for the wallet harness HTTP API.
 */
package com.elevenid.marty.wallet

import kotlinx.serialization.Serializable

// ── Health ─────────────────────────────────────────────────────────────

@Serializable
data class HealthResponse(
    val status: String,
    val service: String,
    val openid4vciVersion: String,
    val openid4vpVersion: String,
    val capabilities: WalletCapabilities,
)

@Serializable
data class WalletCapabilities(
    val officialOid4vciIssuance: Boolean,
    val officialOid4vpPresentation: Boolean,
    val officialOid4vpFormats: List<String>,
    val holderBinding: String,
    val compatibilityOnlyFormats: List<String>,
)

@Serializable
data class ErrorResponse(
    val error: String,
    val message: String,
    val stackTrace: String,
)

// ── Issuance ──────────────────────────────────────────────────────────────

@Serializable
data class IssuanceRequest(
    val credentialOfferUri: String,
    val txCode: String? = null,
)

@Serializable
data class IssuanceResult(
    val success: Boolean,
    val credentialCount: Int = 0,
    val credentials: List<CredentialInfo> = emptyList(),
    val issuerMetadata: IssuerMetadataInfo? = null,
    val error: String? = null,
)

@Serializable
data class CredentialInfo(
    val format: String,
    val credential: String,
    val notificationId: String? = null,
)

@Serializable
data class IssuerMetadataInfo(
    val credentialIssuerId: String,
    val credentialConfigurationIds: List<String>,
    val authorizationServers: List<String>,
    val tokenEndpoint: String? = null,
    val credentialEndpoint: String? = null,
    val nonceEndpoint: String? = null,
    val parEndpoint: String? = null,
)

@Serializable
data class OfferResolutionResult(
    val success: Boolean,
    val issuerMetadata: IssuerMetadataInfo? = null,
    val grantType: String? = null,
    val credentialConfigurationIds: List<String> = emptyList(),
    val error: String? = null,
)

// ── Presentation ──────────────────────────────────────────────────────────

@Serializable
data class PresentationRequest(
    val authorizationRequestUri: String,
    val credential: String,
)

@Serializable
data class DirectPostRequest(
    val responseUri: String,
    val vpToken: String,
    val presentationSubmission: String? = null,
    val state: String? = null,
)

@Serializable
data class PresentationResult(
    val success: Boolean,
    val responseMode: String? = null,
    val redirectUri: String? = null,
    val verifierAccepted: Boolean = false,
    val responseStatus: Int? = null,
    val responseBody: String? = null,
    val error: String? = null,
)

@Serializable
data class BuildVpTokenRequest(
    val credential: String,
    val audience: String,
    val nonce: String,
    val format: String = "dc+sd-jwt",
)

@Serializable
data class BuildVpTokenResponse(
    val vpToken: String,
)

/*
 * Wallet issuance service — wraps eudi-lib-jvm-openid4vci-kt.
 *
 * Uses the exact same library that powers the EUDI Reference Wallet to
 * exercise Marty's OID4VCI endpoints, proving real wallet compatibility.
 */
package com.elevenid.marty.wallet

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.plugins.logging.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.net.URI
import java.security.Signature
import java.security.interfaces.ECPrivateKey

object WalletIssuanceService {
    private val log = LoggerFactory.getLogger(javaClass)

    /**
     * OpenId4VCI configuration matching the EUDI Reference Wallet's defaults.
     * Public client with P-256 key, supporting credential response encryption.
     */
    private val vciConfig = OpenId4VCIConfig(
        clientAuthentication = ClientAuthentication.None("marty-eudi-harness"),
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
        encryptionSupportConfig = EncryptionSupportConfig(
            Curve.P_256,
            2048,
            CredentialResponseEncryptionPolicy.SUPPORTED,
        ),
        parUsage = ParUsage.IfSupported,
        issuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    )

    private fun createHttpClient(): HttpClient = HttpClient(Java) {
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
        install(HttpCookies)
        install(Logging) {
            logger = Logger.DEFAULT
            level = LogLevel.INFO
        }
    }

    /**
     * Create a P-256 BatchSigner for proof-of-possession.
     * This mirrors what the EUDI Reference Wallet does internally.
     * javaAlgorithm must be the JCA name ("SHA256withECDSA"), which
     * the EUDI library maps to JWS alg "ES256".
     */
    private fun createP256ProofSigner(): ProofsSpecification {
        val ecKey: ECKey = ECKeyGenerator(Curve.P_256).generate()
        val publicJwk = ecKey.toPublicJWK()
        val privateKey: ECPrivateKey = ecKey.toECPrivateKey()
        val bindingKey = JwtBindingKey.Jwk(publicJwk)
        val jcaAlgorithm = "SHA256withECDSA"

        val batchSigner = object : BatchSigner<JwtBindingKey> {
            override val javaAlgorithm: String = jcaAlgorithm

            override suspend fun authenticate(): BatchSignOperation<JwtBindingKey> {
                val signOp = SignOperation<JwtBindingKey>(
                    function = SignFunction { input ->
                        val sig = Signature.getInstance(jcaAlgorithm)
                        sig.initSign(privateKey)
                        sig.update(input)
                        sig.sign()
                    },
                    publicMaterial = bindingKey,
                )
                return BatchSignOperation(listOf(signOp))
            }

            override suspend fun release(signOps: BatchSignOperation<JwtBindingKey>?) {
                // no-op
            }
        }

        return ProofsSpecification.JwtProofs.NoKeyAttestation(batchSigner)
    }

    /**
     * Resolve a credential offer URI — validates metadata, checks grant types.
     * This alone exercises a significant portion of the OID4VCI spec.
     */
    suspend fun resolveOffer(credentialOfferUri: String): OfferResolutionResult =
        coroutineScope {
            createHttpClient().use { httpClient ->
                try {
                    val issuer = Issuer.make(vciConfig, credentialOfferUri, httpClient).getOrThrow()
                    val offer = issuer.credentialOffer
                    val meta = offer.credentialIssuerMetadata

                    val grantType = when (offer.grants) {
                        is Grants.PreAuthorizedCode -> "pre-authorized_code"
                        is Grants.AuthorizationCode -> "authorization_code"
                        is Grants.Both -> "both"
                        null -> "none"
                    }

                    OfferResolutionResult(
                        success = true,
                        issuerMetadata = extractMetadata(meta),
                        grantType = grantType,
                        credentialConfigurationIds = offer.credentialConfigurationIdentifiers
                            .map { it.value },
                    )
                } catch (e: Exception) {
                    log.error("Offer resolution failed", e)
                    OfferResolutionResult(
                        success = false,
                        error = "${e::class.simpleName}: ${e.message}",
                    )
                }
            }
        }

    /**
     * Full pre-authorized code issuance flow using the EUDI Wallet Kit.
     *
     * Steps (all handled by the library):
     * 1. Resolve credential offer URI → fetch + validate issuer metadata
     * 2. Authorize with pre-authorized code
     * 3. Generate proof-of-possession JWT (P-256)
     * 4. Request credential(s) from the credential endpoint
     * 5. Return issued credential(s)
     */
    suspend fun runPreAuthIssuance(
        credentialOfferUri: String,
        txCode: String? = null,
    ): IssuanceResult = coroutineScope {
        createHttpClient().use { httpClient ->
            try {
                // Step 1: Resolve offer
                log.info("Resolving credential offer: $credentialOfferUri")
                val issuer = Issuer.make(vciConfig, credentialOfferUri, httpClient).getOrThrow()
                val offer = issuer.credentialOffer
                val meta = offer.credentialIssuerMetadata

                log.info(
                    "Resolved issuer: {} with {} credential configs",
                    meta.credentialIssuerIdentifier.toString(),
                    offer.credentialConfigurationIdentifiers.size,
                )

                // Verify pre-auth grant is available
                require(
                    offer.grants is Grants.PreAuthorizedCode || offer.grants is Grants.Both
                ) { "Offer does not support pre-authorized code grant" }

                // Step 2: Authorize
                log.info("Authorizing with pre-authorized code (txCode=${txCode != null})")
                val authorized = with(issuer) {
                    authorizeWithPreAuthorizationCode(txCode).getOrThrow()
                }
                log.info("Authorization successful")

                // Step 3-4: Request each credential
                val credentials = mutableListOf<CredentialInfo>()
                var currentAuth = authorized

                for (credCfgId in offer.credentialConfigurationIdentifiers) {
                    log.info("Requesting credential: ${credCfgId.value}")
                    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credCfgId)

                    // Generate P-256 proof signer (same as EUDI Reference Wallet)
                    val popSigner = createP256ProofSigner()

                    val (updatedAuth, outcome) = with(issuer) {
                        currentAuth.request(requestPayload, popSigner).getOrThrow()
                    }
                    currentAuth = updatedAuth

                    when (outcome) {
                        is SubmissionOutcome.Success -> {
                            for (cred in outcome.credentials) {
                                val credStr = when (val c = cred.credential) {
                                    is Credential.Str -> c.value
                                    is Credential.Json -> c.value.toString()
                                }
                                credentials.add(CredentialInfo(
                                    format = credCfgId.value,
                                    credential = credStr,
                                    notificationId = outcome.notificationId?.value,
                                ))
                            }
                            log.info("Credential issued for: ${credCfgId.value}")
                        }
                        is SubmissionOutcome.Deferred -> {
                            log.info("Got deferred issuance for ${credCfgId.value}")
                            val (_, deferredOutcome) = with(issuer) {
                                currentAuth.queryForDeferredCredential(outcome.transactionId).getOrThrow()
                            }
                            when (deferredOutcome) {
                                is DeferredCredentialQueryOutcome.Issued -> {
                                    for (cred in deferredOutcome.credentials) {
                                        val credStr = when (val c = cred.credential) {
                                            is Credential.Str -> c.value
                                            is Credential.Json -> c.value.toString()
                                        }
                                        credentials.add(CredentialInfo(
                                            format = credCfgId.value,
                                            credential = credStr,
                                            notificationId = deferredOutcome.notificationId?.value,
                                        ))
                                    }
                                }
                                is DeferredCredentialQueryOutcome.IssuancePending ->
                                    log.warn("Deferred issuance still pending for ${credCfgId.value}")
                                is DeferredCredentialQueryOutcome.Errored ->
                                    log.warn("Deferred issuance errored for ${credCfgId.value}: ${deferredOutcome.error}")
                            }
                        }
                        is SubmissionOutcome.Failed -> {
                            throw RuntimeException(
                                "Credential request failed for ${credCfgId.value}: ${outcome.error.message}"
                            )
                        }
                    }
                }

                IssuanceResult(
                    success = true,
                    credentialCount = credentials.size,
                    credentials = credentials,
                    issuerMetadata = extractMetadata(meta),
                )
            } catch (e: Exception) {
                log.error("Pre-auth issuance failed", e)
                IssuanceResult(
                    success = false,
                    error = "${e::class.simpleName}: ${e.message}",
                )
            }
        }
    }

    private fun extractMetadata(meta: CredentialIssuerMetadata): IssuerMetadataInfo {
        return IssuerMetadataInfo(
            credentialIssuerId = meta.credentialIssuerIdentifier.toString(),
            credentialConfigurationIds = meta.credentialConfigurationsSupported.keys
                .map { it.value },
            authorizationServers = meta.authorizationServers.map { it.toString() },
            tokenEndpoint = null, // available on auth server metadata
            credentialEndpoint = meta.credentialEndpoint.toString(),
            nonceEndpoint = meta.nonceEndpoint?.toString(),
            parEndpoint = null,
        )
    }
}

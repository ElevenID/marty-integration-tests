package com.elevenid.marty.wallet

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.buildCborMap
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseSign1
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.SignatureVerificationException
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.mdoc.response.DeviceResponse
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.time.Instant

class WalletPresentationServiceTest {
    @Test
    @OptIn(kotlin.time.ExperimentalTime::class)
    fun `mdoc presentation preserves issuer data and authenticates with the holder key`() {
        runBlocking {
            val holderKey = ECKeyGenerator(Curve.P_256).generate()
            val holderPrivateKey = EcPrivateKey.fromJwk(
                Json.parseToJsonElement(holderKey.toJSONString()).jsonObject,
            )
            val mobileSecurityObject = MobileSecurityObject(
                version = "1.0",
                docType = MDL_DOC_TYPE,
                signedAt = Instant.parse("2026-01-01T00:00:00Z"),
                validFrom = Instant.parse("2026-01-01T00:00:00Z"),
                validUntil = Instant.parse("2027-01-01T00:00:00Z"),
                expectedUpdate = null,
                digestAlgorithm = Algorithm.SHA256,
                valueDigests = emptyMap(),
                deviceKey = holderPrivateKey.publicKey,
            )
            val issuerSigned = buildCborMap {
                put("nameSpaces", buildIssuerNamespaces {}.toDataItem())
                put(
                    "issuerAuth",
                    CoseSign1(
                        protectedHeaders = emptyMap(),
                        unprotectedHeaders = emptyMap(),
                        signature = byteArrayOf(1, 2, 3),
                        payload = Cbor.encode(
                            Tagged(
                                Tagged.ENCODED_CBOR,
                                Bstr(
                                    Cbor.encode(mobileSecurityObject.toDataItem()),
                                ),
                            ),
                        ),
                    ).toDataItem(),
                )
            }
            val issuedCompact = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Cbor.encode(issuerSigned))

            val presentedCompact = WalletPresentationService.buildMdocDeviceResponse(
                issuedCredentialCompact = issuedCompact,
                holderKey = holderKey,
                audience = AUDIENCE,
                nonce = NONCE,
                responseUri = RESPONSE_URI,
                responseEncryptionJwkThumbprint = null,
            )

            val presented = Cbor.decode(Base64.getUrlDecoder().decode(presentedCompact))
            val parsedReferenceResponse = DeviceResponse.fromDataItem(presented)
            val document = presented["documents"].asArray.single()
            assertEquals("1.0", parsedReferenceResponse.version)
            assertEquals(DeviceResponse.STATUS_OK, parsedReferenceResponse.status)
            assertEquals("1.0", presented["version"].asTstr)
            assertEquals(0L, presented["status"].asNumber)
            assertEquals(MDL_DOC_TYPE, document["docType"].asTstr)
            assertContentEquals(
                Cbor.encode(issuerSigned["issuerAuth"]),
                Cbor.encode(document["issuerSigned"]["issuerAuth"]),
            )
            assertContentEquals(
                Cbor.encode(issuerSigned["nameSpaces"]),
                Cbor.encode(document["issuerSigned"]["nameSpaces"]),
            )
            assertContentEquals(
                Cbor.encode(buildCborMap {}),
                Cbor.encode(document["deviceSigned"]["nameSpaces"].asTaggedEncodedCbor),
            )

            val sessionTranscript = WalletPresentationService.mdocSessionTranscript(
                audience = AUDIENCE,
                nonce = NONCE,
                responseUri = RESPONSE_URI,
                responseEncryptionJwkThumbprint = null,
            )
            val deviceAuthentication = WalletPresentationService.mdocDeviceAuthenticationBytes(
                sessionTranscript = sessionTranscript,
                docType = MDL_DOC_TYPE,
                deviceNamespaces = Cbor.encode(buildCborMap {}),
            )
            val signature = document["deviceSigned"]["deviceAuth"]["deviceSignature"].asCoseSign1

            Cose.coseSign1Check(
                publicKey = holderPrivateKey.publicKey,
                detachedData = deviceAuthentication,
                signature = signature,
                signatureAlgorithm = Algorithm.ES256,
            )

            val wrongTranscript = WalletPresentationService.mdocSessionTranscript(
                audience = AUDIENCE,
                nonce = "different-nonce",
                responseUri = RESPONSE_URI,
                responseEncryptionJwkThumbprint = null,
            )
            val wrongDeviceAuthentication = WalletPresentationService.mdocDeviceAuthenticationBytes(
                sessionTranscript = wrongTranscript,
                docType = MDL_DOC_TYPE,
                deviceNamespaces = Cbor.encode(buildCborMap {}),
            )
            assertFailsWith<SignatureVerificationException> {
                Cose.coseSign1Check(
                    publicKey = holderPrivateKey.publicKey,
                    detachedData = wrongDeviceAuthentication,
                    signature = signature,
                    signatureAlgorithm = Algorithm.ES256,
                )
            }
        }
    }

    @Test
    fun `openid4vp handover binds audience nonce response uri and encryption key`() = runBlocking {
        val baseline = WalletPresentationService.mdocSessionTranscript(
            audience = AUDIENCE,
            nonce = NONCE,
            responseUri = RESPONSE_URI,
            responseEncryptionJwkThumbprint = null,
        )
        val variants = listOf(
            WalletPresentationService.mdocSessionTranscript(
                audience = "different-client",
                nonce = NONCE,
                responseUri = RESPONSE_URI,
                responseEncryptionJwkThumbprint = null,
            ),
            WalletPresentationService.mdocSessionTranscript(
                audience = AUDIENCE,
                nonce = "different-nonce",
                responseUri = RESPONSE_URI,
                responseEncryptionJwkThumbprint = null,
            ),
            WalletPresentationService.mdocSessionTranscript(
                audience = AUDIENCE,
                nonce = NONCE,
                responseUri = "https://verifier.example/different",
                responseEncryptionJwkThumbprint = null,
            ),
            WalletPresentationService.mdocSessionTranscript(
                audience = AUDIENCE,
                nonce = NONCE,
                responseUri = RESPONSE_URI,
                responseEncryptionJwkThumbprint = byteArrayOf(1, 2, 3),
            ),
        )

        variants.forEach { variant ->
            assertNotEquals(
                Base64.getEncoder().encodeToString(baseline),
                Base64.getEncoder().encodeToString(variant),
            )
        }
    }

    @Test
    fun `presentation diagnostics expose only stage and root exception class`() {
        val code = WalletPresentationService.presentationErrorCode(
            IllegalStateException(
                "must not escape",
                IllegalArgumentException("credential and DID must not escape"),
            ),
            "build-mso_mdoc",
        )

        assertEquals(
            "presentation-build-mso-mdoc-illegal-argument-exception",
            code,
        )
        assertEquals(false, code.contains("credential"))
        assertEquals(false, code.contains("did"))
    }

    @Test
    fun `mdoc presentation diagnostics include a value-free operation stage`() {
        val exception = assertFailsWith<RuntimeException> {
            runBlocking {
                WalletPresentationService.buildMdocDeviceResponse(
                    issuedCredentialCompact = "must-not-escape",
                    holderKey = ECKeyGenerator(Curve.P_256).generate().toPublicJWK(),
                    audience = AUDIENCE,
                    nonce = NONCE,
                    responseUri = RESPONSE_URI,
                    responseEncryptionJwkThumbprint = null,
                )
            }
        }
        val code = WalletPresentationService.presentationErrorCode(exception, "build-mso_mdoc")

        assertEquals(
            "presentation-build-mso-mdoc-validate-input-illegal-argument-exception",
            code,
        )
        assertEquals(false, code.contains("must-not-escape"))
    }

    private companion object {
        const val MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
        const val AUDIENCE = "x509_hash:verifier.example"
        const val NONCE = "openid4vp-nonce"
        const val RESPONSE_URI = "https://verifier.example/direct_post"
    }
}

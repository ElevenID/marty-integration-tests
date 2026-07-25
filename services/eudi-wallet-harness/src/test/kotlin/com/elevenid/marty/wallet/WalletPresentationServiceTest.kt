package com.elevenid.marty.wallet

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.putCborArray
import org.multipaz.cose.Cose
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.SignatureVerificationException
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class WalletPresentationServiceTest {
    @Test
    fun `mdoc presentation preserves issuer data and authenticates with the holder key`() {
        runBlocking {
            val holderKey = ECKeyGenerator(Curve.P_256).generate()
            val issuerSigned = buildCborMap {
                put("opaque", "issuer-signed-data")
            }
            val issuedResponse = buildCborMap {
                put("version", "1.0")
                putCborArray("documents") {
                    add(
                        buildCborMap {
                            put("docType", MDL_DOC_TYPE)
                            put("issuerSigned", issuerSigned)
                        },
                    )
                }
                put("status", 0)
            }
            val issuedCompact = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Cbor.encode(issuedResponse))

            val presentedCompact = WalletPresentationService.buildMdocDeviceResponse(
                issuedCredentialCompact = issuedCompact,
                holderKey = holderKey,
                audience = AUDIENCE,
                nonce = NONCE,
                responseUri = RESPONSE_URI,
                responseEncryptionJwkThumbprint = null,
            )

            val presented = Cbor.decode(Base64.getUrlDecoder().decode(presentedCompact))
            val document = presented["documents"].asArray.single()
            assertEquals("1.0", presented["version"].asTstr)
            assertEquals(0L, presented["status"].asNumber)
            assertEquals(MDL_DOC_TYPE, document["docType"].asTstr)
            assertContentEquals(Cbor.encode(issuerSigned), Cbor.encode(document["issuerSigned"]))
            assertContentEquals(
                Cbor.encode(buildCborMap {}),
                Cbor.encode(document["deviceSigned"]["nameSpaces"].asTaggedEncodedCbor),
            )

            val holderPrivateKey = EcPrivateKey.fromJwk(
                Json.parseToJsonElement(holderKey.toJSONString()).jsonObject,
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

    private companion object {
        const val MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
        const val AUDIENCE = "x509_hash:verifier.example"
        const val NONCE = "openid4vp-nonce"
        const val RESPONSE_URI = "https://verifier.example/direct_post"
    }
}

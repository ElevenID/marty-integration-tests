package com.elevenid.marty.wallet

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestException
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestValidationError
import java.security.Signature
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WalletIssuanceServiceTest {
    @Test
    fun `unsupported upstream grants remain a bounded failure without private reason`() {
        val error = CredentialOfferRequestException(
            CredentialOfferRequestValidationError.UnsupportedGrants(
                IllegalArgumentException("private-offer-reason-canary"),
            ),
        )
        assertEquals("offer-grants-unsupported", WalletIssuanceService.offerResolutionErrorCode(error))
        assertEquals(
            "offer-grants-unsupported",
            WalletIssuanceService.offerResolutionErrorCode(RuntimeException(error)),
        )
    }

    @Test
    fun `holder proof callback returns JCA DER ECDSA signature`() {
        val key = ECKeyGenerator(Curve.P_256).generate()
        val payload = "current-eudi-holder-proof".encodeToByteArray()

        val signature = WalletIssuanceService.derEncodedEcdsaSignature(key, payload)

        assertTrue(signature.isNotEmpty())
        assertTrue(signature.first() == 0x30.toByte(), "ECDSA signature is not a DER sequence")
        assertTrue(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key.toECPublicKey())
                update(payload)
                verify(signature)
            },
        )
        assertFalse(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key.toECPublicKey())
                update("tampered".encodeToByteArray())
                verify(signature)
            },
        )
    }
}

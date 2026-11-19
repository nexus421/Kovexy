package bayern.kickner.kovexy.auth

import bayern.kickner.kovexy.cleanText
import kotlinx.serialization.json.*
import kotnexlib.ResultOf2
import java.security.MessageDigest
import java.util.*

/**
 * The claims Kovexy uses from a validated ID token.
 *
 * @property sub Stable user ID at the provider, checked against `oidc.allowedSubjects`.
 * @property name Display name: `name`, falling back to `preferred_username`, both cleaned with [cleanText]. If neither
 *   is left after cleaning, the raw `sub`, uncleaned.
 * @property email The `email` claim, cleaned, `null` if missing or not confirmed by `email_verified` (true or "true"):
 *   an unconfirmed address is whatever the user typed in (decided on 19.11.2026).
 * @property preferredUsername The `preferred_username` claim, cleaned, `null` if missing.
 */
data class IdTokenClaims(val sub: String, val name: String, val email: String? = null, val preferredUsername: String? = null)

/**
 * Longest display name Kovexy keeps. Users choose their name at the provider, so it is cut and stripped of control and
 * formatting characters before it reaches pages, the audit log and the program log.
 */
const val MAX_NAME_LENGTH = 80

/**
 * Validates an ID token received directly from the token endpoint.
 *
 * The signature is deliberately not checked. OpenID Connect Core 1.0 section 3.1.3.7 allows the TLS server
 * validation of the token endpoint to replace the signature check when the token comes straight from that endpoint,
 * which is the only way Kovexy ever receives one. That saves a JWT library and a JWKS cache. Everything else is
 * checked: `iss` byte for byte, `aud` contains the client ID (and `azp` matches if there are several audiences),
 * `exp` in the future, `iat` not in the future, `nonce` equal to the one sent with the authorization request.
 *
 * @param idToken The compact JWT.
 * @param issuer Expected `iss`.
 * @param clientId Expected audience.
 * @param nonce The nonce of this login attempt.
 * @param nowSeconds Current Unix time in seconds.
 * @param leewaySeconds Tolerated clock skew between Kovexy and the provider.
 * @return the claims, or a reason for the log (never shown with token contents).
 */
fun validateIdToken(
    idToken: String,
    issuer: String,
    clientId: String,
    nonce: String,
    nowSeconds: Long,
    leewaySeconds: Long = 60,
): ResultOf2<IdTokenClaims, String> {
    val parts = idToken.split('.')
    if (parts.size != 3) return ResultOf2.Failure("ID token is not a compact JWT")

    val payload = runCatching {
        Json.parseToJsonElement(Base64.getUrlDecoder().decode(parts[1]).decodeToString()).jsonObject
    }.getOrElse { return ResultOf2.Failure("ID token payload is not valid JSON") }

    val iss = payload.string("iss")
    if (iss != issuer) return ResultOf2.Failure("Unexpected issuer \"$iss\"")

    val audiences = when (val aud = payload["aud"]) {
        is JsonPrimitive -> listOfNotNull(aud.contentOrNull)
        is JsonArray -> aud.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        else -> emptyList()
    }
    if (clientId !in audiences) return ResultOf2.Failure("ID token was not issued for this client")
    val azpMismatch = audiences.size > 1 && payload.string("azp") != clientId
    if (azpMismatch) return ResultOf2.Failure("ID token has several audiences and azp is not this client")

    val exp = payload.long("exp") ?: return ResultOf2.Failure("ID token has no exp")
    if (nowSeconds > exp + leewaySeconds) return ResultOf2.Failure("ID token expired")
    val iat = payload.long("iat")
    if (iat != null && iat > nowSeconds + leewaySeconds) return ResultOf2.Failure("ID token issued in the future")

    val tokenNonce = payload.string("nonce") ?: return ResultOf2.Failure("ID token has no nonce")
    if (constantTimeEquals(tokenNonce, nonce).not()) return ResultOf2.Failure("ID token nonce does not match")

    val sub = payload.string("sub")
    if (sub.isNullOrBlank()) return ResultOf2.Failure("ID token has no sub")

    val name = listOf("name", "preferred_username").firstNotNullOfOrNull { claim -> payload.string(claim)?.let { cleanText(it, MAX_NAME_LENGTH) } } ?: sub
    val verified = (payload["email_verified"] as? JsonPrimitive)?.content?.equals("true", ignoreCase = true) == true
    val email = payload.string("email")?.takeIf { verified }?.let { cleanText(it, MAX_NAME_LENGTH * 2) }
    val preferred = payload.string("preferred_username")?.let { cleanText(it, MAX_NAME_LENGTH) }
    return ResultOf2.Success(IdTokenClaims(sub, name, email, preferred))
}

/** Compares two strings without leaking the position of the first difference through timing. */
fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull

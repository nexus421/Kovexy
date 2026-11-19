package bayern.kickner.kovexy

import io.ktor.http.Parameters
import io.ktor.http.parseQueryString
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveChannel
import io.ktor.utils.io.readRemaining
import kotlinx.io.readByteArray

/** Largest form body the admin UI reads. The biggest form (an access profile or a webhook template) stays far below. */
const val MAX_FORM_BYTES = 1L shl 20

/** Largest form body on the proxied domains (captcha answer, a reCAPTCHA token is about 2 KB). */
const val MAX_PUBLIC_FORM_BYTES = 16L * 1024

/**
 * Reads a form (`application/x-www-form-urlencoded`) with a size limit, unlike Ktor's `receiveParameters`, which
 * reads any body into memory. A bigger body counts as an empty form, so the form is refused like any incomplete one.
 */
suspend fun ApplicationCall.receiveForm(maxBytes: Long = MAX_FORM_BYTES): Parameters {
    val bytes = receiveChannel().readRemaining(maxBytes + 1).readByteArray()
    if (bytes.size > maxBytes) return Parameters.Empty
    return parseQueryString(bytes.decodeToString())
}

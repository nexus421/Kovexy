package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.LETS_ENCRYPT_PRODUCTION
import bayern.kickner.kovexy.config.isValidHostName
import bayern.kickner.kovexy.formatTimestamp
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FormMethod
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr

/** Certificates and ACME settings, like Zoraxy's "TLS / SSL certificates" and "ACME Client". */
fun Route.certificateRoutes(kovexy: Kovexy) {
    get("/certificates") { call.certificatePage(kovexy, emptyList(), null) }

    post("/certificates/acme") {
        val params = call.receiveForm()
        val directory = params["directory"].orEmpty().trim().ifEmpty { LETS_ENCRYPT_PRODUCTION }
        val problems = call.saveConfig(params["version"]) {
            it.copy(acme = it.acme.copy(directory = directory, staging = params["staging"] != null, email = params["email"].orEmpty().trim()))
        }
        if (problems == null) return@post call.respondRedirect("/certificates?done=acme-saved")
        call.certificatePage(kovexy, problems, params["version"])
    }

    post("/certificates/renew") {
        val domain = call.receiveForm()["domain"].orEmpty()
        if (isValidHostName(domain).not() || domain !in kovexy.routing.tlsDomains()) {
            return@post call.errorPage(HttpStatusCode.BadRequest, "Unknown domain", "No enabled site uses this domain on the TLS listener.")
        }
        kovexy.certificates.renewNow(domain)
        call.respondRedirect("/certificates?done=renew-started")
    }
}

private suspend fun ApplicationCall.certificatePage(kovexy: Kovexy, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val acme = kovexy.config.acme
    val now = kovexy.clock()
    val certs = kovexy.certificates.status()
    page("Certificates", session, Nav.CERTIFICATES, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Certificates", "One certificate per domain, from ACME with the HTTP-01 challenge on port 80. Checked every 10 minutes, renewed in the last third of the lifetime.")
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            if (certs.isEmpty()) p("muted") { +"No domain on the TLS listener yet." }
            else div("table-wrap") {
                table("stack-mobile") {
                    thead { tr { th { +"Domain" }; th { +"State" }; th { +"Valid until" }; th { +"Issuer" }; th { } } }
                    tbody {
                        certs.forEach { cert ->
                            tr {
                                td { attributes["data-label"] = "Domain"; +cert.domain }
                                td {
                                    attributes["data-label"] = "State"
                                    if (cert.wanted.not()) pill("", "unused, not renewed") else certificatePill(cert, now)
                                    cert.lastError?.let { p("muted small break") { +it } }
                                    cert.nextAttempt?.let { p("muted small") { +"Next attempt ${formatTimestamp(it)}" } }
                                }
                                td("nowrap") { attributes["data-label"] = "Valid until"; +(cert.notAfter?.let(::formatTimestamp) ?: "-") }
                                td { attributes["data-label"] = "Issuer"; span("small break") { +(cert.issuer ?: "-") } }
                                td("actions") {
                                    if (cert.wanted) postButton("/certificates/renew", "Renew now", "sm", hidden = mapOf("domain" to cert.domain))
                                }
                            }
                        }
                    }
                }
            }
        }
        card("ACME", "gap-top") {
            p("muted") {
                +"Using ACME means agreeing to the terms of service of the CA, for Let's Encrypt at letsencrypt.org/repository. "
                +"Port 80 must be reachable from the internet for the domains."
            }
            form(action = "/certificates/acme", method = FormMethod.post, classes = "form") {
                versionField(version)
                textField("Directory", "directory", acme.directory, hint = "Let's Encrypt production by default.")
                checkField("Use Let's Encrypt staging", "staging", acme.staging, "for tests, browsers do not trust these certificates")
                textField("Contact mail", "email", acme.email, required = false, hint = "Optional.")
                div("btn-row") { submit("Save ACME settings") }
            }
        }
    }
}

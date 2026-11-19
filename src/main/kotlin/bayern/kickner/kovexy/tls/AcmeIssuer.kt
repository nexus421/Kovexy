package bayern.kickner.kovexy.tls

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.Status
import org.shredzone.acme4j.challenge.Http01Challenge
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

private const val TAG = "Acme"

/** Path prefix of HTTP-01 challenges on port 80. */
const val ACME_CHALLENGE_PREFIX = "/.well-known/acme-challenge/"

/** Time an order may take until the CA validated the domain and issued the certificate. */
private val ORDER_TIMEOUT = 3.minutes

/**
 * Open HTTP-01 challenges: token to key authorization. The proxy answers `/.well-known/acme-challenge/<token>` on
 * port 80 from here, before any other rule.
 */
class ChallengeStore {
    private val tokens = ConcurrentHashMap<String, String>()

    /** Adds a challenge. */
    fun put(token: String, keyAuthorization: String) {
        tokens[token] = keyAuthorization
    }

    /** Removes a challenge after the order finished. */
    fun remove(token: String) {
        tokens.remove(token)
    }

    /** The key authorization for [token], `null` for an unknown token. */
    fun answer(token: String): String? = tokens[token]
}

/** Gets a certificate for one domain. Blocking, may take minutes. */
fun interface CertificateIssuer {
    /**
     * Orders a certificate for [domain] from the ACME CA at [directory].
     *
     * @throws Exception with a readable message if the order fails.
     */
    fun issue(domain: String, directory: String): CertificateBundle
}

/**
 * Orders certificates with acme4j and the HTTP-01 challenge. One account key for every CA, it lives in the
 * [CertStore]. Every certificate gets its own new EC P-256 key.
 *
 * Using ACME means agreeing to the terms of service of the CA, like with Caddy.
 *
 * @param store Holds the account key.
 * @param challenges Where the challenge answers go for the proxy to serve them.
 * @param email Optional contact address for the account, read for every order so a change applies at once.
 */
class Acme4jIssuer(
    private val store: CertStore,
    private val challenges: ChallengeStore,
    private val email: () -> String,
) : CertificateIssuer {

    override fun issue(domain: String, directory: String): CertificateBundle {
        val session = Session(directory)
        val accountBuilder = AccountBuilder()
            .agreeToTermsOfService()
            .useKeyPair(store.loadOrCreateAccountKey())
        email().takeIf { it.isNotBlank() }?.let { accountBuilder.addEmail(it) }
        val account = accountBuilder.create(session)
        // An existing account comes back unchanged, a new e-mail address has to be sent on its own
        val contact = email().takeIf { it.isNotBlank() }?.let { java.net.URI("mailto:$it") }
        if (contact != null && account.contacts != listOf(contact)) {
            runCatching { account.modify().apply { contacts.clear(); addEmail(email()) }.commit() }
        }

        val order = account.newOrder().domain(domain).create()
        val tokens = mutableListOf<String>()
        try {
            order.authorizations.filter { it.status != Status.VALID }.forEach { authorization ->
                val challenge = authorization.findChallenge(Http01Challenge::class.java)
                    .orElseThrow { IllegalStateException("The CA offers no HTTP-01 challenge for $domain") }
                challenges.put(challenge.token, challenge.authorization)
                tokens += challenge.token
                challenge.trigger()
                val status = authorization.waitForCompletion(ORDER_TIMEOUT.toJavaDuration())
                if (status != Status.VALID) {
                    val problem = challenge.error.map { it.toString() }.orElse("status $status")
                    throw IllegalStateException("Validation of $domain failed: $problem")
                }
            }
            order.waitUntilReady(ORDER_TIMEOUT.toJavaDuration())
            val key = newEcKeyPair()
            order.execute(key)
            val status = order.waitForCompletion(ORDER_TIMEOUT.toJavaDuration())
            if (status != Status.VALID) {
                val problem = order.error.map { it.toString() }.orElse("status $status")
                throw IllegalStateException("Order for $domain failed: $problem")
            }
            val chain = order.certificate.certificateChain
            staticLog(KLogger.Level.INFO, TAG) { "Certificate for $domain issued by $directory, valid until ${chain.first().notAfter}" }
            return CertificateBundle(key.private, chain.toTypedArray())
        } finally {
            tokens.forEach(challenges::remove)
        }
    }
}

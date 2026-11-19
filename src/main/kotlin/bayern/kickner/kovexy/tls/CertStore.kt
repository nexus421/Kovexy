package bayern.kickner.kovexy.tls

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.isValidHostName
import bayern.kickner.kovexy.config.writeAtomically
import bayern.kickner.kovexy.ensurePrivateDir
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.StringReader
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.time.Duration.Companion.days

private const val TAG = "CertStore"

/** Lifetime of the self-signed fallback certificate. */
private val FALLBACK_LIFETIME = (100 * 365).days

/** Name of the chain file in a domain directory. */
const val CHAIN_FILE = "fullchain.pem"

/** Name of the key file in a domain directory. */
const val KEY_FILE = "privkey.pem"

/**
 * A certificate with its key.
 *
 * @property key The private key.
 * @property chain Leaf first, then the intermediates.
 */
class CertificateBundle(val key: PrivateKey, val chain: Array<X509Certificate>) {
    /** The leaf certificate. */
    val leaf: X509Certificate get() = chain.first()
}

/**
 * Certificates and keys on disk, in `<dataDir>/certs`:
 *
 * - `<domain>/fullchain.pem` and `<domain>/privkey.pem` for every domain,
 * - `fallback/` for the self-signed fallback certificate,
 * - `acme/account.pem` for the key of the ACME account.
 *
 * Directories are `0700`, files `0600`.
 *
 * @param dir The `certs` directory.
 */
class CertStore(val dir: File) {

    /** Directory of the fallback certificate. */
    private val fallbackDir = File(dir, "fallback")

    /** Key of the ACME account. */
    val accountKeyFile = File(File(dir, "acme"), "account.pem")

    /**
     * Loads the fallback certificate, creating a self-signed EC P-256 one on the first start.
     */
    fun loadOrCreateFallback(): CertificateBundle {
        read(fallbackDir)?.let { return it }
        val pair = newEcKeyPair()
        val cert = selfSigned(pair, "kovexy-fallback")
        write(fallbackDir, CertificateBundle(pair.private, arrayOf(cert)))
        staticLog(KLogger.Level.INFO, TAG) { "Created the self-signed fallback certificate" }
        return CertificateBundle(pair.private, arrayOf(cert))
    }

    /** The stored certificate of [domain], `null` if there is none or it cannot be read. */
    fun load(domain: String): CertificateBundle? {
        if (isValidHostName(domain).not()) return null
        return read(File(dir, domain))
    }

    /** Stores the certificate of [domain], replacing an older one. */
    fun save(domain: String, bundle: CertificateBundle) {
        require(isValidHostName(domain)) { "Invalid domain" }
        write(File(dir, domain), bundle)
    }

    /** Deletes the stored certificate of [domain]. The fallback and the ACME account are never touched. */
    fun delete(domain: String) {
        if (isValidHostName(domain).not() || domain == "fallback" || domain == "acme") return
        File(dir, domain).deleteRecursively()
    }

    /** Every domain with a stored certificate. */
    fun storedDomains(): List<String> = dir.listFiles { f ->
        f.isDirectory && f.name != "fallback" && f.name != "acme" && File(f, CHAIN_FILE).isFile && isValidHostName(f.name)
    }
        ?.map { it.name }?.sorted().orEmpty()

    /** Loads the ACME account key, creating an EC P-256 key on first use. */
    fun loadOrCreateAccountKey(): KeyPair {
        if (accountKeyFile.isFile) {
            val pair = runCatching { readKeyPair(accountKeyFile.readText()) }.getOrNull()
            if (pair != null) return pair
            staticLog(KLogger.Level.WARN, TAG) { "${accountKeyFile.absolutePath} is unreadable, creating a new ACME account key" }
        }
        val pair = newEcKeyPair()
        ensurePrivateDir(accountKeyFile.parentFile)
        // Private key (PKCS#8) and public key in one file: the JDK's EC keys encode without the public point
        writeAtomically(accountKeyFile, privateKeyPem(pair.private) + toPem(pair.public))
        return pair
    }

    private fun read(domainDir: File): CertificateBundle? {
        val chainFile = File(domainDir, CHAIN_FILE)
        val keyFile = File(domainDir, KEY_FILE)
        if (chainFile.isFile.not() || keyFile.isFile.not()) return null
        return runCatching {
            val chain = parseCertificates(chainFile.readText())
            val key = requireNotNull(readPrivateKey(keyFile.readText())) { "no private key" }
            require(chain.isNotEmpty()) { "no certificate" }
            // Key and chain are two files, a crash between writing them leaves a pair that does not belong together
            require(keyMatches(key, chain.first())) { "the private key does not belong to the certificate" }
            CertificateBundle(key, chain.toTypedArray())
        }.onFailure {
            staticLog(KLogger.Level.ERROR, TAG) { "Cannot read the certificate in ${domainDir.absolutePath}: ${it.message}" }
        }.getOrNull()
    }

    private fun write(domainDir: File, bundle: CertificateBundle) {
        ensurePrivateDir(dir)
        ensurePrivateDir(domainDir)
        // Key first: a crash in between leaves the old chain with a new key, which read() refuses, so it gets renewed
        writeAtomically(File(domainDir, KEY_FILE), privateKeyPem(bundle.key))
        writeAtomically(File(domainDir, CHAIN_FILE), bundle.chain.joinToString("") { toPem(it) })
    }
}

/** A new EC P-256 key pair, the key type of the PoC and of Caddy's default. */
fun newEcKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

/** A self-signed certificate for [commonName], used for the fallback and in tests. */
fun selfSigned(pair: KeyPair, commonName: String, validFrom: Date = Date(), lifetimeMillis: Long = FALLBACK_LIFETIME.inWholeMilliseconds): X509Certificate {
    val name = X500Name("CN=$commonName")
    val builder = JcaX509v3CertificateBuilder(
        name,
        BigInteger.valueOf(System.nanoTime()),
        validFrom,
        Date(validFrom.time + lifetimeMillis),
        name,
        pair.public,
    ).addExtension(Extension.basicConstraints, true, BasicConstraints(false))
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(pair.private)
    return JcaX509CertificateConverter().getCertificate(builder.build(signer))
}

/** PEM text of a key or certificate. */
fun toPem(value: Any): String = StringWriter().also { out -> JcaPEMWriter(out).use { it.writeObject(value) } }.toString()

/** All certificates in a PEM text, in file order. */
fun parseCertificates(pem: String): List<X509Certificate> =
    CertificateFactory.getInstance("X.509").generateCertificates(pem.byteInputStream()).map { it as X509Certificate }

/** A private key as PEM in PKCS#8 form (`BEGIN PRIVATE KEY`). */
fun privateKeyPem(key: PrivateKey): String = toPem(JcaPKCS8Generator(key, null).generate())

/** A key pair from a PEM text with a private key and its public key, `null` if one of them is missing. */
fun readKeyPair(pem: String): KeyPair? = PEMParser(StringReader(pem)).use { parser ->
    val converter = JcaPEMKeyConverter()
    var private: PrivateKey? = null
    var public: java.security.PublicKey? = null
    while (true) {
        when (val value = parser.readObject() ?: break) {
            is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> private = converter.getPrivateKey(value)
            is org.bouncycastle.asn1.x509.SubjectPublicKeyInfo -> public = converter.getPublicKey(value)
        }
    }
    if (private != null && public != null) KeyPair(public, private) else null
}

/** A private key from a PEM text, PKCS#8 or the classic EC and RSA forms, `null` if the text holds none. */
fun readPrivateKey(pem: String): PrivateKey? = PEMParser(StringReader(pem)).use { parser ->
    when (val value = parser.readObject()) {
        is PEMKeyPair -> JcaPEMKeyConverter().getPrivateKey(value.privateKeyInfo)
        is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> JcaPEMKeyConverter().getPrivateKey(value)
        else -> null
    }
}

/** Whether [key] belongs to [certificate]: a signature made with the key verifies with the certificate's public key. */
internal fun keyMatches(key: java.security.PrivateKey, certificate: java.security.cert.X509Certificate): Boolean = runCatching {
    val algorithm = if (key.algorithm == "EC") "SHA256withECDSA" else "SHA256withRSA"
    val nonce = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
    val signature = java.security.Signature.getInstance(algorithm).run {
        initSign(key)
        update(nonce)
        sign()
    }
    java.security.Signature.getInstance(algorithm).run {
        initVerify(certificate.publicKey)
        update(nonce)
        verify(signature)
    }
}.getOrDefault(false)

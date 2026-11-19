package bayern.kickner.kovexy.auth

import bayern.kickner.kovexy.randomToken
import bayern.kickner.kovexy.secureRandom
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.MessageDigest
import java.util.Base64

/** Memory cost in KiB, 64 MiB like Dirl. Well above the OWASP minimum of 19 MiB. */
private const val MEMORY_KIB = 65536

/** Number of passes. */
private const val ITERATIONS = 3

/** Number of lanes. */
private const val PARALLELISM = 1

/** Length of the derived hash in bytes. */
private const val HASH_BYTES = 32

/** Length of the random salt in bytes. */
private const val SALT_BYTES = 16

/** Upper bounds for parameters read from the file, a manipulated hash must not exhaust the heap or hang the login. */
private const val MAX_MEMORY_KIB = 1024 * 1024
private const val MAX_ITERATIONS = 20
private const val MAX_PARALLELISM = 16

/** Length of a generated admin password: 18 random bytes give 24 characters and 144 bits. */
private const val GENERATED_PASSWORD_BYTES = 18

/** Shortest password the UI accepts. */
const val MIN_PASSWORD_LENGTH = 12

/** Basic Auth passwords may have any length, below this one the admin UI only hints (decided on 18.11.2026). */
const val RECOMMENDED_PASSWORD_LENGTH = 12

private val b64 = Base64.getEncoder().withoutPadding()
private val b64Decoder = Base64.getDecoder()
private val phc = """\${'$'}argon2id\${'$'}v=19\${'$'}m=(\d+),t=(\d+),p=(\d+)\${'$'}([A-Za-z0-9+/]+)\${'$'}([A-Za-z0-9+/]+)""".toRegex()

/**
 * A parsed Argon2id hash.
 *
 * @property memoryKiB Memory cost.
 * @property iterations Passes.
 * @property parallelism Lanes.
 * @property salt Random salt.
 * @property hash Derived hash.
 */
private class PhcHash(val memoryKiB: Int, val iterations: Int, val parallelism: Int, val salt: ByteArray, val hash: ByteArray)

private fun parsePhc(text: String): PhcHash? {
    val match = phc.matchEntire(text) ?: return null
    val (m, t, p, salt, hash) = match.destructured
    val memory = m.toIntOrNull() ?: return null
    val iterations = t.toIntOrNull() ?: return null
    val parallelism = p.toIntOrNull() ?: return null
    if (memory !in 8..MAX_MEMORY_KIB || iterations !in 1..MAX_ITERATIONS || parallelism !in 1..MAX_PARALLELISM) return null
    val saltBytes = runCatching { b64Decoder.decode(salt) }.getOrNull() ?: return null
    val hashBytes = runCatching { b64Decoder.decode(hash) }.getOrNull() ?: return null
    if (saltBytes.size < 8 || hashBytes.size < 16) return null
    return PhcHash(memory, iterations, parallelism, saltBytes, hashBytes)
}

private fun derive(password: String, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray {
    val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withMemoryAsKB(memoryKiB)
        .withIterations(iterations)
        .withParallelism(parallelism)
        .withSalt(salt)
        .build()
    val out = ByteArray(length)
    Argon2BytesGenerator().apply { init(params) }.generateBytes(password.toCharArray(), out)
    return out
}

/**
 * Hashes [password] with Argon2id and returns it in the PHC string format, e.g.
 * `$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`, which stores the parameters next to the hash.
 */
fun hashPassword(password: String): String {
    val salt = ByteArray(SALT_BYTES).also(secureRandom::nextBytes)
    val hash = derive(password, salt, MEMORY_KIB, ITERATIONS, PARALLELISM, HASH_BYTES)
    return "\$argon2id\$v=19\$m=$MEMORY_KIB,t=$ITERATIONS,p=$PARALLELISM\$${b64.encodeToString(salt)}\$${b64.encodeToString(hash)}"
}

/** Whether [hash] is an Argon2id hash in PHC format with parameters inside the accepted bounds. */
fun isValidPasswordHash(hash: String): Boolean = parsePhc(hash) != null

/**
 * Checks [password] against [hash] in constant time.
 *
 * @return `false` also for a malformed hash.
 */
fun verifyPassword(password: String, hash: String): Boolean {
    val parsed = parsePhc(hash) ?: return false
    val candidate = derive(password, parsed.salt, parsed.memoryKiB, parsed.iterations, parsed.parallelism, parsed.hash.size)
    return MessageDigest.isEqual(candidate, parsed.hash)
}

/** A new random admin password, URL-safe Base64 so it can be typed and copied without surprises. */
fun generatePassword(): String = randomToken(GENERATED_PASSWORD_BYTES)

/** bcrypt cost of Basic Auth hashes, like Caddy. */
const val BCRYPT_COST = 14

private val bcryptFormat = """\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}""".toRegex()

/** A bcrypt hash of [password] with [BCRYPT_COST], in the `$2b$` form. Takes about a second on purpose. */
fun hashBcrypt(password: String, cost: Int = BCRYPT_COST): String =
    org.bouncycastle.crypto.generators.OpenBSDBCrypt.generate("2b", password.toCharArray(), ByteArray(16).also(secureRandom::nextBytes), cost)

/** Whether [hash] is a bcrypt hash with a cost Kovexy accepts (4 to 16, higher would hang every login). */
fun isValidBcryptHash(hash: String): Boolean {
    val match = bcryptFormat.matchEntire(hash) ?: return false
    return match.groupValues[1].toInt() in 4..16
}

/**
 * Checks a Basic Auth password against a bcrypt or Argon2id hash.
 *
 * @return `false` also for a malformed hash.
 */
fun verifyBasicAuthHash(password: String, hash: String): Boolean = when {
    isValidBcryptHash(hash) -> runCatching { org.bouncycastle.crypto.generators.OpenBSDBCrypt.checkPassword(hash, password.toCharArray()) }.getOrDefault(false)
    isValidPasswordHash(hash) -> verifyPassword(password, hash)
    else -> false
}

package bayern.kickner.kovexy.audit

import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.encodeConfig

/** Shown instead of every secret in the audit log. */
const val MASK = "***"

/** Longest config, in lines, that is diffed line by line. Larger ones only get a note. */
private const val MAX_DIFF_LINES = 4000

/**
 * The config with every secret replaced by [MASK]: password hash, OIDC client secrets (admin and apps), Basic Auth
 * hashes, reCAPTCHA secret keys and the values of webhook headers (they usually hold API keys). Empty values stay empty, so the diff still shows when a secret
 * was set or removed.
 */
fun maskSecrets(config: KovexyConfig): KovexyConfig = config.copy(
    admin = config.admin.copy(
        passwordHash = config.admin.passwordHash.mask(),
        oidc = config.admin.oidc?.let { it.copy(clientSecret = it.clientSecret.mask()) },
    ),
    accessProfiles = config.accessProfiles.map { profile ->
        profile.copy(
            basicAuth = profile.basicAuth?.let { auth -> auth.copy(users = auth.users.map { it.copy(hash = it.hash.mask()) }) },
            captcha = profile.captcha?.let { it.copy(secretKey = it.secretKey.mask()) },
        )
    },
    appAuth = config.appAuth?.let { it.copy(clientSecret = it.clientSecret.mask()) },
    webhooks = config.webhooks.map { hook -> hook.copy(url = maskUrl(hook.url), headers = hook.headers.mapValues { it.value.mask() }) },
)

private fun String.mask(): String = if (isEmpty()) "" else MASK

/** Scheme and host of a webhook URL only: Discord, Slack and Telegram carry the token in the path. */
private fun maskUrl(url: String): String {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return url.mask()
    val rest = url.length > "${uri.scheme}://${uri.rawAuthority}".length
    return "${uri.scheme}://${uri.host ?: ""}${if (uri.port > 0) ":${uri.port}" else ""}${if (rest) "/$MASK" else ""}"
}

/** Names of the secrets that differ between [old] and [new], so the diff can say so without showing them. */
private fun secretChanges(old: KovexyConfig, new: KovexyConfig): List<String> = buildList {
    if (old.admin.passwordHash != new.admin.passwordHash) add("admin.passwordHash")
    if (old.admin.oidc?.clientSecret != new.admin.oidc?.clientSecret) add("admin.oidc.clientSecret")
    if (old.appAuth?.clientSecret != new.appAuth?.clientSecret && old.appAuth != null && new.appAuth != null) add("appAuth.clientSecret")
    new.accessProfiles.forEach { profile ->
        val oldCaptcha = old.accessProfiles.firstOrNull { it.name == profile.name }?.captcha
        if (oldCaptcha != null && profile.captcha != null && oldCaptcha.secretKey != profile.captcha.secretKey) add("reCAPTCHA secret key in profile ${profile.name}")
        val before = old.accessProfiles.firstOrNull { it.name == profile.name }?.basicAuth?.users.orEmpty().associate { it.name to it.hash }
        profile.basicAuth?.users?.forEach { user ->
            if (before[user.name] != null && before[user.name] != user.hash) add("password of Basic Auth user ${user.name} in profile ${profile.name}")
        }
    }
    new.webhooks.forEach { hook ->
        val oldUrl = old.webhooks.firstOrNull { it.name == hook.name }?.url
        if (oldUrl != null && oldUrl != hook.url) add("URL of webhook ${hook.name}")
        val before = old.webhooks.firstOrNull { it.name == hook.name }?.headers.orEmpty()
        hook.headers.forEach { (name, value) -> if (before[name] != null && before[name] != value) add("header $name of webhook ${hook.name}") }
    }
}

/**
 * The difference between two config versions as lines with `-` and `+`, like a unified diff without context, with
 * secrets masked. A changed secret is named in a line `* changed: ...`, its value never appears.
 *
 * @return the diff, `"no visible change"` if only formatting changed.
 */
fun configDiff(old: KovexyConfig?, new: KovexyConfig): String {
    val a = old?.let { encodeConfig(maskSecrets(it)).lines() } ?: emptyList()
    val b = encodeConfig(maskSecrets(new)).lines()
    if (a.size > MAX_DIFF_LINES || b.size > MAX_DIFF_LINES) return "Config too large for a line diff (${a.size} and ${b.size} lines)"
    // Longest common subsequence, the configs are small enough for the quadratic table
    val lcs = Array(a.size + 1) { IntArray(b.size + 1) }
    for (i in a.indices.reversed()) for (j in b.indices.reversed()) {
        lcs[i][j] = if (a[i] == b[j]) lcs[i + 1][j + 1] + 1 else maxOf(lcs[i + 1][j], lcs[i][j + 1])
    }
    val out = StringBuilder()
    var i = 0
    var j = 0
    while (i < a.size || j < b.size) {
        when {
            i < a.size && j < b.size && a[i] == b[j] -> {
                i++
                j++
            }

            j < b.size && (i == a.size || lcs[i][j + 1] >= lcs[i + 1][j]) -> out.append("+ ").append(b[j++]).append('\n')
            else -> out.append("- ").append(a[i++]).append('\n')
        }
    }
    old?.let { secretChanges(it, new) }?.forEach { out.append("* changed: ").append(it).append('\n') }
    return out.toString().trimEnd().ifEmpty { "no visible change" }
}

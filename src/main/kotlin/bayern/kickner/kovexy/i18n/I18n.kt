package bayern.kickner.kovexy.i18n

import kotlinx.serialization.json.Json
import java.util.concurrent.ConcurrentHashMap

/** Code of the language the admin UI is written in, no dictionary needed. */
const val DEFAULT_LANGUAGE = "en"

/**
 * The languages of the admin UI: code to its name in that language. English is built in, every other language is a
 * dictionary `i18n/<code>.json` in the resources (English text to text in that language). A new language is a new
 * file and one more entry here.
 */
val LANGUAGES: Map<String, String> = linkedMapOf("en" to "English", "de" to "Deutsch")

/**
 * The language of the admin UI, changed live with the config. Only what the admin UI shows is translated. Logs, error
 * messages of the config check, webhook texts, the docs and everything visitors see stay English.
 */
object I18n {
    /** Code of the current language, see [LANGUAGES]. */
    @Volatile
    var language: String = DEFAULT_LANGUAGE

    /** Tests only: gets every text that has no translation in the current language. */
    @Volatile
    var onMissing: ((String) -> Unit)? = null

    private val json = Json { ignoreUnknownKeys = true }
    private val dictionaries = ConcurrentHashMap<String, Map<String, String>>()

    /** The dictionary of [code], empty if there is none. */
    fun dictionary(code: String): Map<String, String> = dictionaries.getOrPut(code) {
        val text = I18n::class.java.getResourceAsStream("/i18n/$code.json")?.use { it.readBytes().decodeToString() }
        if (text == null) emptyMap() else json.decodeFromString<Map<String, String>>(text)
    }

    /** [text] in the current language, [text] itself if there is no translation. */
    fun translate(text: String): String {
        val code = language
        if (code == DEFAULT_LANGUAGE) return text
        dictionary(code)[text]?.let { return it }
        // A helper translates again what its caller already translated, that is no missing text
        if (text in translatedTexts(code)) return text
        if (looksLikeText(text)) onMissing?.invoke(text)
        return text
    }

    private val values = ConcurrentHashMap<String, Set<String>>()

    private fun translatedTexts(code: String): Set<String> = values.getOrPut(code) { dictionary(code).values.toHashSet() }

    /**
     * Whether [text] is something to translate and not a name or an address that happens to pass through a helper: a
     * sentence with words, or one capitalized word.
     */
    private fun looksLikeText(text: String): Boolean {
        if (text.isBlank()) return false
        if (' ' in text) return Regex("[A-Za-z]{3,}").containsMatchIn(text)
        return text.first().isLetter() && text.first().isUpperCase() && text.all { it.isLetter() || it == '-' || it == '\'' }
    }
}

/**
 * [text] in the language of the admin UI. `{0}`, `{1}` and so on in the text are replaced by [args], in every language,
 * so a translation can put them in another order.
 */
fun t(text: String, vararg args: Any?): String {
    var out = I18n.translate(text)
    args.forEachIndexed { i, arg -> out = out.replace("{$i}", arg.toString()) }
    return out
}

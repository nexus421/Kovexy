package bayern.kickner.kovexy

import bayern.kickner.kovexy.web.helpFor
import bayern.kickner.kovexy.web.helpKeys
import kotlin.test.Test
import kotlin.test.assertTrue

/** The help texts follow the writing rules of the project and are all filled in. */
class HelpTextsTest {
    @Test
    fun textsAreWellFormed(): Unit {
        assertTrue(helpKeys().size > 80, "Help texts exist for the fields")
        helpKeys().forEach { key ->
            val help = helpFor(key)!!
            val texts = listOfNotNull(help.what, help.effect, help.recommended)
            assertTrue(help.what.isNotBlank(), "$key has no text")
            texts.forEach { text ->
                assertTrue(text == text.trim(), "$key has spaces around its text")
                // No em dash, no en dash and no semicolon in prose (CLAUDE.md)
                assertTrue('\u2014' !in text && '\u2013' !in text && ';' !in text, "$key breaks the writing rules: $text")
                assertTrue(text.length < 520, "$key is too long for a tooltip: ${text.length} characters")
            }
        }
    }
}

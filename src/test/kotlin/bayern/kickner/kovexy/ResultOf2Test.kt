package bayern.kickner.kovexy

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals

/** The result type that carries expected outcomes instead of exceptions. */
class ResultOf2Test {
    private fun parse(text: String): ResultOf2<Int, String> =
        text.toIntOrNull()?.let { ResultOf2.Success(it) } ?: ResultOf2.Failure("not a number: $text")

    @Test
    fun aSuccessCarriesItsValue() {
        val result = parse("42")
        assertIs<ResultOf2.Success<Int>>(result)
        assertEquals(42, result.value)
    }

    @Test
    fun aFailureCarriesItsReason() {
        val result = parse("x")
        assertIs<ResultOf2.Failure<String>>(result)
        assertEquals("not a number: x", result.value)
    }

    @Test
    fun aWhenOverBothCasesNeedsNoElseBranch() {
        // Does not compile if the type is not sealed, so callers can rely on exhaustive handling
        fun describe(result: ResultOf2<Int, String>): String = when (result) {
            is ResultOf2.Success -> "ok ${result.value}"
            is ResultOf2.Failure -> "failed ${result.value}"
        }
        assertEquals("ok 1", describe(parse("1")))
        assertEquals("failed not a number: y", describe(parse("y")))
    }

    @Test
    fun resultsAreComparedByTheirContent() {
        assertEquals(ResultOf2.Success(1), ResultOf2.Success(1))
        assertEquals(ResultOf2.Failure("a"), ResultOf2.Failure("a"))
        assertNotEquals<ResultOf2<Int, Int>>(ResultOf2.Success(1), ResultOf2.Failure(1), "Same value, different case")
    }

    @Test
    fun aStarProjectionAcceptsAnyResult() {
        // Main.report takes ResultOf2<*, SaveError>, the success type does not matter there
        val results: List<ResultOf2<*, String>> = listOf(ResultOf2.Success(1), ResultOf2.Success("a"), ResultOf2.Failure("no"))
        assertEquals(2, results.count { it is ResultOf2.Success })
    }
}

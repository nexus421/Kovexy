package bayern.kickner.kovexy

/**
 * The outcome of something that can fail in an expected way, instead of an exception: either a [Success] with a
 * value or a [Failure] with the reason. Sealed, so a `when` over both cases needs no `else`.
 *
 * @param S Type of the value of a success.
 * @param F Type of the reason of a failure.
 */
sealed interface ResultOf2<out S, out F> {
    /** It worked. [value] is the result. */
    data class Success<out S>(val value: S) : ResultOf2<S, Nothing>

    /** It did not work. [value] says why. */
    data class Failure<out F>(val value: F) : ResultOf2<Nothing, F>
}

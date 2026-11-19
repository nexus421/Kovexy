package bayern.kickner.kovexy.site

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.http.content.LocalPathContent
import io.ktor.http.defaultForFile
import io.ktor.http.withCharset
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/** Index files, in this order, like Zoraxy. */
val INDEX_FILES = listOf("index.html", "index.htm")

/**
 * What a static answer did.
 *
 * @property status Status code sent.
 * @property bytes Body bytes sent.
 */
data class StaticResult(val status: Int, val bytes: Long)

/**
 * Serves a file below [root].
 *
 * - The path is the normalized request path below the location, so `..` cannot leave [root]. Symbolic links that
 *   point outside of [root] are refused as well.
 * - A directory without trailing slash is redirected to the path with slash (`308`, like Caddy).
 * - A directory gets `index.html`, then `index.htm`, otherwise a listing if [listing] is on (off by default, a
 *   listing easily shows files nobody meant to publish), otherwise 404.
 * - Only `GET` and `HEAD`, other methods get 405.
 * - `Last-Modified` and `If-Modified-Since` are supported.
 *
 * @param requestPath The full request path, for the redirect and the listing heading.
 * @param relative The normalized path below the location, starting with `/`.
 * @param extraHeaders Response headers of the location, applied to every answer.
 */
suspend fun ApplicationCall.serveStatic(
    root: File,
    requestPath: String,
    relative: String,
    listing: Boolean,
    extraHeaders: (ApplicationCall) -> Unit,
): StaticResult {
    val method = request.httpMethod
    if (method != HttpMethod.Get && method != HttpMethod.Head) {
        extraHeaders(this)
        response.headers.append(HttpHeaders.Allow, "GET, HEAD")
        respondText(neutralPage(405, "Method Not Allowed", "This address only serves files."), ContentType.Text.Html.withCharset(Charsets.UTF_8), HttpStatusCode.MethodNotAllowed)
        return StaticResult(405, 0)
    }

    val rootPath = runCatching { root.toPath().toRealPath() }.getOrNull() ?: return notFound(extraHeaders)
    // A path the file system cannot take (NUL and the like) is simply not there
    val target = runCatching { rootPath.resolve(relative.removePrefix("/")).normalize() }.getOrNull() ?: return notFound(extraHeaders)
    if (target.startsWith(rootPath).not() || Files.exists(target).not()) return notFound(extraHeaders)
    if (hidden(rootPath, target)) return notFound(extraHeaders)
    val real = contained(rootPath, target) ?: return notFound(extraHeaders)

    if (Files.isDirectory(real)) {
        if (requestPath.endsWith("/").not()) {
            extraHeaders(this)
            val query = request.local.uri.substringAfter('?', "").let { if (it.isEmpty()) "" else "?$it" }
            response.headers.append(HttpHeaders.Location, "$requestPath/$query")
            respond(HttpStatusCode.PermanentRedirect)
            return StaticResult(308, 0)
        }
        // The index file gets the same checks as a requested file, a symlinked index.html must not leave the root
        INDEX_FILES.map { real.resolve(it) }.firstOrNull { Files.isRegularFile(it) }?.let { index ->
            val safe = contained(rootPath, index)?.takeIf { Files.isRegularFile(it) } ?: return notFound(extraHeaders)
            return sendFile(safe, extraHeaders)
        }
        if (listing.not()) return notFound(extraHeaders)
        val entries = Files.list(real).use { stream ->
            stream.filter { it.fileName.toString().startsWith(".").not() }
                .map { if (Files.isDirectory(it)) "${it.fileName}/" else it.fileName.toString() }.toList()
        }.sortedWith(compareBy<String> { it.endsWith("/").not() }.thenBy { it.lowercase() })
        val html = directoryListingPage(requestPath, entries)
        extraHeaders(this)
        respondText(html, ContentType.Text.Html.withCharset(Charsets.UTF_8))
        return StaticResult(200, html.toByteArray().size.toLong())
    }
    if (Files.isRegularFile(real).not()) return notFound(extraHeaders)
    return sendFile(real, extraHeaders)
}

private val httpDate: DateTimeFormatter = DateTimeFormatter.RFC_1123_DATE_TIME

private suspend fun ApplicationCall.sendFile(path: Path, extraHeaders: (ApplicationCall) -> Unit): StaticResult {
    val modified = Files.getLastModifiedTime(path).toMillis() / 1000 * 1000
    val since = request.headers[HttpHeaders.IfModifiedSince]?.let {
        runCatching { ZonedDateTime.parse(it, httpDate).toInstant().toEpochMilli() }.getOrNull()
    }
    extraHeaders(this)
    response.headers.append(HttpHeaders.LastModified, httpDate.format(ZonedDateTime.ofInstant(java.time.Instant.ofEpochMilli(modified), ZoneOffset.UTC)))
    if (since != null && modified <= since) {
        respond(HttpStatusCode.NotModified)
        return StaticResult(304, 0)
    }
    val type = ContentType.defaultForFile(path.toFile())
    respond(LocalPathContent(path, type))
    return StaticResult(200, if (request.httpMethod == HttpMethod.Head) 0 else Files.size(path))
}

private suspend fun ApplicationCall.notFound(extraHeaders: (ApplicationCall) -> Unit): StaticResult {
    extraHeaders(this)
    respondText(notFoundPage(), ContentType.Text.Html.withCharset(Charsets.UTF_8), HttpStatusCode.NotFound)
    return StaticResult(404, 0)
}

/** Hidden files and directories (.git, .env) are never served or listed, only .well-known is public by convention. */
private fun hidden(root: Path, path: Path): Boolean = root.relativize(path).any { it.toString().startsWith(".") && it.toString() != ".well-known" }

/** The real path of [path] if it stays inside [root] (also through symbolic links) and is not hidden there, else `null`. */
private fun contained(root: Path, path: Path): Path? =
    runCatching { path.toRealPath() }.getOrNull()?.takeIf { it.startsWith(root) && hidden(root, it).not() }

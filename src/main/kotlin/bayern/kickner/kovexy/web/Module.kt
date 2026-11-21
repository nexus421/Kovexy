package bayern.kickner.kovexy.web

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.proxy.MAX_VISITOR_WEBSOCKET_FRAME_BYTES
import io.ktor.websocket.ChannelOverflow
import bayern.kickner.kovexy.proxy.WEBSOCKET_QUEUE_FRAMES
import bayern.kickner.kovexy.audit.Actor
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.LoadedConfig
import bayern.kickner.kovexy.config.SaveError
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.http.content.staticResources
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.ContentTransformationException
import io.ktor.server.request.path
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.sse.SSE
import io.ktor.server.websocket.WebSockets
import io.ktor.util.AttributeKey
import kotlinx.coroutines.CancellationException
import kotlinx.html.p
import bayern.kickner.kovexy.ResultOf2

private const val TAG = "Admin"

/** The [Kovexy] of the running application, for code that only has the call, like the page layout. */
val KovexyKey = AttributeKey<Kovexy>("kovexy")

/**
 * The Ktor module. Requests on a proxy port go to the proxy before any routing and never see the admin UI, every
 * other request is the admin UI with its guards and error pages.
 */
fun Application.kovexyModule(kovexy: Kovexy) {
    attributes.put(KovexyKey, kovexy)
    // Frames of proxied WebSockets pass unchanged, so no masking of Kovexy's own. The size limit keeps a single frame
    // header from making Kovexy allocate up to 2 GiB
    install(WebSockets) {
        masking = false
        maxFrameSize = MAX_VISITOR_WEBSOCKET_FRAME_BYTES
        // Bounded and suspending, so a peer that does not read slows the other side down instead of filling the heap
        channels {
            incoming = bounded(WEBSOCKET_QUEUE_FRAMES, ChannelOverflow.SUSPEND)
            outgoing = bounded(WEBSOCKET_QUEUE_FRAMES, ChannelOverflow.SUSPEND)
        }
    }
    install(SSE)
    intercept(ApplicationCallPipeline.Setup) {
        val listener = kovexy.server.listenerFor(call.request.local.localPort)
        if (listener != null) {
            kovexy.proxy.handle(call, listener)
            finish()
            return@intercept
        }
        try {
            if (call.checkAdminRequest(kovexy).not()) {
                finish()
                return@intercept
            }
            proceed()
        } catch (e: CancellationException) {
            throw e
        } catch (e: BadRequestException) {
            call.errorPage(HttpStatusCode.BadRequest, "Bad request", "The request was malformed.")
        } catch (e: ContentTransformationException) {
            call.errorPage(HttpStatusCode.BadRequest, "Bad request", "The request was malformed.")
        } catch (e: Throwable) {
            staticLog(KLogger.Level.ERROR, TAG) { "Request ${call.request.path()} failed: ${e.stackTraceToString()}" }
            runCatching { call.errorPage(HttpStatusCode.InternalServerError, "Something went wrong", "The error was logged. Try again, or check the log on the server.") }
        }
    }

    routing {
        staticResources("/static", "static")
        get("/healthz") { call.respondText("ok") }
        authRoutes(kovexy)
        statusRoutes(kovexy)
        domainRoutes(kovexy)
        backendRoutes(kovexy)
        fallbackRoutes(kovexy)
        certificateRoutes(kovexy)
        statisticsRoutes(kovexy)
        accessLogRoutes(kovexy)
        webhookRoutes(kovexy)
        settingsRoutes(kovexy)
        accessRoutes(kovexy)
        securityRoutes(kovexy)
        incusRoutes(kovexy)
        // Everything else, also known paths with the wrong method
        route("{...}") {
            handle { call.errorPage(HttpStatusCode.NotFound, "Page not found", "This address does not exist in Kovexy.") }
        }
    }
}

/** A styled error page in the admin layout. */
suspend fun ApplicationCall.errorPage(status: HttpStatusCode, title: String, text: String) {
    val session = if (attributes.contains(SessionKey)) attributes[SessionKey] else null
    page(title, session, status = status) {
        pageHeader(title)
        card {
            p("muted") { +text }
            linkButton("/", "Back to the status page", "primary")
        }
    }
}

/** Who makes the request, for the audit log: the logged in admin with their address. */
val ApplicationCall.actor: Actor
    get() = if (attributes.contains(SessionKey)) session.let { Actor(it.sub, it.name, adminClientIp) } else Actor("anonymous", "anonymous", adminClientIp)

/**
 * Changes the config from a form, recorded in the audit log under [actor].
 *
 * @param version The version the form was based on, from [versionField].
 * @return `null` on success, else the problems to show next to the form.
 */
fun ApplicationCall.saveConfig(version: String?, change: (KovexyConfig) -> KovexyConfig): List<String>? =
    when (val result = application.attributes[KovexyKey].configStore.update(version, actor, change)) {
        is ResultOf2.Success<LoadedConfig> -> null
        is ResultOf2.Failure -> when (val error = result.value) {
            is SaveError.Invalid -> error.problems
            SaveError.Conflict -> listOf("The configuration changed since this page was loaded (in another tab or in the file). Open the page again from the menu and apply your change there.")
            is SaveError.Io -> listOf("Saving failed: ${error.message}")
        }
    }

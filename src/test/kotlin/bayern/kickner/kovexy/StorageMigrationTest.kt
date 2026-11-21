package bayern.kickner.kovexy

import bayern.kickner.kovexy.stats.Storage
import bayern.kickner.kovexy.stats.statistics
import java.sql.DriverManager
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals

/** A database from an older version keeps working: new columns are added, old rows keep their values. */
class StorageMigrationTest {
    @Test
    fun oldStatisticsTablesGetTheBlockColumns(): Unit {
        val file = createTempDirectory("kovexy-db").resolve("kovexy.db").toFile()
        try {
            DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}").use { connection ->
                connection.createStatement().use {
                    it.execute(
                        "CREATE TABLE stats_daily (site VARCHAR(253) NOT NULL, bucket BIGINT NOT NULL, requests BIGINT NOT NULL, status_2xx BIGINT NOT NULL, " +
                            "status_3xx BIGINT NOT NULL, status_4xx BIGINT NOT NULL, status_5xx BIGINT NOT NULL, bytes_in BIGINT NOT NULL, bytes_out BIGINT NOT NULL, " +
                            "duration_sum_ms BIGINT NOT NULL, duration_max_ms BIGINT NOT NULL, PRIMARY KEY (site, bucket))"
                    )
                    it.execute("INSERT INTO stats_daily VALUES ('a.test', 1, 5, 5, 0, 0, 0, 0, 0, 0, 0)")
                }
            }
            val row = Storage(file).statistics(hourly = false, from = 0).single()
            assertEquals(5, row.requests)
            assertEquals(0, row.blocked)
            assertEquals(0, row.redirected)
        } finally {
            file.parentFile.deleteRecursively()
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/** Conversions between {@link Instant} and {@code TIMESTAMP WITH TIME ZONE} columns. */
public final class JdbcTimes {

	private JdbcTimes() {
	}

	/** A JDBC parameter for {@code instant}, or null. */
	public static OffsetDateTime param(Instant instant) {
		return (instant == null) ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	/** The column as an instant, or null. */
	public static Instant read(ResultSet rs, String column) throws SQLException {
		OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
		return (value == null) ? null : value.toInstant();
	}

}

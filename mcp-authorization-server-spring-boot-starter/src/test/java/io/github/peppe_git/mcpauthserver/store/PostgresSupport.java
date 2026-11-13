// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import javax.sql.DataSource;

import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** One PostgreSQL container for the JDBC store tests, with the shipped schema applied. */
final class PostgresSupport {

	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine");

	private static DataSource dataSource;

	private PostgresSupport() {
	}

	static synchronized DataSource dataSource() {
		if (dataSource == null) {
			POSTGRES.start();
			DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
					POSTGRES.getPassword());
			new ResourceDatabasePopulator(
					new ClassPathResource("io/github/peppe_git/mcpauthserver/store/schema-postgresql.sql"))
				.execute(ds);
			dataSource = ds;
		}
		return dataSource;
	}

	static JdbcTemplate jdbc() {
		return new JdbcTemplate(dataSource());
	}

	static TransactionTemplate tx() {
		return new TransactionTemplate(new DataSourceTransactionManager(dataSource()));
	}

	static void truncate() {
		jdbc().execute("TRUNCATE mcp_oauth_token, mcp_oauth_grant, mcp_oauth_authorization_code, "
				+ "mcp_oauth_authorization_request, mcp_oauth_client");
	}

}

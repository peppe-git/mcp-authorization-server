// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
class JdbcGrantStoreTest extends GrantStoreContract {

	@Override
	GrantStore newStore() {
		PostgresSupport.truncate();
		return new JdbcGrantStore(PostgresSupport.jdbc(), PostgresSupport.tx());
	}

	@Test
	void onlyHashesAreStored() {
		String rows = PostgresSupport.jdbc()
			.queryForList("SELECT access_hash || refresh_hash FROM mcp_oauth_token", String.class)
			.toString();
		assertThat(rows).doesNotContain("r0").contains(hash("r0"));
	}

}

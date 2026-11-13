// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
class JdbcAuthorizationStateStoreTest extends AuthorizationStateStoreContract {

	@Override
	AuthorizationStateStore newStore() {
		PostgresSupport.truncate();
		return new JdbcAuthorizationStateStore(PostgresSupport.jdbc(), PostgresSupport.tx());
	}

}

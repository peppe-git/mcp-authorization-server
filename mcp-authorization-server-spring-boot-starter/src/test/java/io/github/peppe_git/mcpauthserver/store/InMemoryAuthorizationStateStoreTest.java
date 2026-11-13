// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

class InMemoryAuthorizationStateStoreTest extends AuthorizationStateStoreContract {

	@Override
	AuthorizationStateStore newStore() {
		return new InMemoryAuthorizationStateStore();
	}

}

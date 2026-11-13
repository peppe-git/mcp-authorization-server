// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

class InMemoryGrantStoreTest extends GrantStoreContract {

	@Override
	GrantStore newStore() {
		return new InMemoryGrantStore();
	}

}

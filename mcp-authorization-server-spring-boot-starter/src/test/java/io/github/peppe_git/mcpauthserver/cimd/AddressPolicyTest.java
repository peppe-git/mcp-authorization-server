// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.Inet6Address;
import java.net.InetAddress;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AddressPolicyTest {

	@ParameterizedTest
	@ValueSource(strings = {
			// IPv4 special-purpose blocks
			"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.254", "127.0.0.1", "127.255.0.9",
			"169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.88.99.1", "192.168.1.1",
			"198.18.0.1", "198.19.255.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1",
			"255.255.255.255",
			// IPv6 special-purpose and non-global
			"::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1", "100::1", "2001:db8::1",
			"3fff::1", "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:10::1", "2001:20::1",
			// IPv4 embedded in IPv6 pointing inside
			"::ffff:0:7f00:1", "::127.0.0.1", "::10.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
			"64:ff9b::a00:1", "64:ff9b:1::8.8.8.8", "64:ff9b:1::1", "2002:7f00:1::", "2002:a00:1::1",
			"2002:a9fe:a9fe::1", "2002:c0a8:101::" })
	void blocked(String literal) throws Exception {
		assertThat(AddressPolicy.isAllowed(parse(literal))).as(literal).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = { "8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.1", "172.15.0.1",
			"172.32.0.1", "192.0.1.1", "192.169.0.1", "198.17.0.1", "223.255.255.255", "2606:4700:4700::1111",
			"2a00:1450:4001:80b::200e", "2001:4860:4860::8888", "2001:200::1",
			// embedded IPv4 that is itself public
			"64:ff9b::808:808", "2002:808:808::1" })
	void allowed(String literal) throws Exception {
		assertThat(AddressPolicy.isAllowed(parse(literal))).as(literal).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254" })
	void ipv4MappedJudgedAsIpv4EvenWhenBuiltAsIpv6(String literal) throws Exception {
		// The JDK parses these as Inet4Address; an Inet6Address built from the raw bytes must be judged the same.
		InetAddress parsed = InetAddress.getByName(literal);
		InetAddress raw = Inet6Address.getByAddress(null, toMapped(parsed.getAddress()), null);
		assertThat(AddressPolicy.isAllowed(parsed)).isFalse();
		assertThat(AddressPolicy.isAllowed(raw)).isFalse();
	}

	private static byte[] toMapped(byte[] v4) {
		byte[] b = new byte[16];
		b[10] = (byte) 0xff;
		b[11] = (byte) 0xff;
		System.arraycopy(v4, 0, b, 12, 4);
		return b;
	}

	private static InetAddress parse(String literal) throws Exception {
		// Literals only: InetAddress.getByName does not query DNS for them.
		return InetAddress.getByName(literal);
	}

}

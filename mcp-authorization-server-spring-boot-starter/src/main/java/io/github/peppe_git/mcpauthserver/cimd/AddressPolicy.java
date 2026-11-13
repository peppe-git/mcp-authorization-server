// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.cimd;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

/**
 * Decides whether the server may connect to an address when it fetches a Client ID Metadata Document.
 *
 * <p>The rule is an allow list, not a deny list: only global unicast addresses pass.
 * <ul>
 * <li><b>IPv4</b>: everything except the special-purpose blocks of RFC 6890 and its updates (this
 * network, private, shared address space / CGNAT, loopback, link-local, IETF protocol assignments,
 * documentation, the deprecated 6to4 relay anycast, benchmarking, multicast, reserved and broadcast).</li>
 * <li><b>IPv6</b>: only {@code 2000::/3}, minus {@code 2001::/23} (IETF protocol assignments, including
 * Teredo {@code 2001::/32}), {@code 2001:db8::/32} and {@code 3fff::/20} (documentation).</li>
 * <li><b>IPv4 embedded in IPv6</b> is judged as the IPv4 address it carries, because a translator in
 * the deployment network may deliver the packet there: IPv4-mapped {@code ::ffff:0:0/96}, NAT64
 * well-known prefix {@code 64:ff9b::/96} and 6to4 {@code 2002::/16}. IPv4-compatible
 * {@code ::/96}, IPv4-translated {@code ::ffff:0:0:0/96} and local-use NAT64 {@code 64:ff9b:1::/48}
 * (whose mapping is site-specific) are rejected outright.</li>
 * </ul>
 * A library cannot know whether the network it runs in has NAT64 or 6to4 gateways, so it assumes that
 * it might.
 */
public final class AddressPolicy {

	private AddressPolicy() {
	}

	/** True if a metadata document may be fetched from {@code address}. */
	public static boolean isAllowed(InetAddress address) {
		if (address instanceof Inet4Address) {
			return isGlobalIpv4(address.getAddress());
		}
		if (address instanceof Inet6Address) {
			return isAllowedIpv6(address.getAddress());
		}
		return false;
	}

	static boolean isGlobalIpv4(byte[] b) {
		int a0 = b[0] & 0xff;
		int a1 = b[1] & 0xff;
		int a2 = b[2] & 0xff;
		if (a0 == 0 // 0.0.0.0/8 this network
				|| a0 == 10 // 10.0.0.0/8 private
				|| (a0 == 100 && a1 >= 64 && a1 <= 127) // 100.64.0.0/10 shared address space (CGNAT)
				|| a0 == 127 // 127.0.0.0/8 loopback
				|| (a0 == 169 && a1 == 254) // 169.254.0.0/16 link-local, cloud metadata
				|| (a0 == 172 && a1 >= 16 && a1 <= 31) // 172.16.0.0/12 private
				|| (a0 == 192 && a1 == 0 && a2 == 0) // 192.0.0.0/24 IETF protocol assignments
				|| (a0 == 192 && a1 == 0 && a2 == 2) // 192.0.2.0/24 documentation
				|| (a0 == 192 && a1 == 88 && a2 == 99) // 192.88.99.0/24 6to4 relay anycast (deprecated)
				|| (a0 == 192 && a1 == 168) // 192.168.0.0/16 private
				|| (a0 == 198 && (a1 == 18 || a1 == 19)) // 198.18.0.0/15 benchmarking
				|| (a0 == 198 && a1 == 51 && a2 == 100) // 198.51.100.0/24 documentation
				|| (a0 == 203 && a1 == 0 && a2 == 113) // 203.0.113.0/24 documentation
				|| a0 >= 224) { // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, broadcast
			return false;
		}
		return true;
	}

	static boolean isAllowedIpv6(byte[] b) {
		// IPv4-mapped ::ffff:a.b.c.d (the JDK usually returns an Inet4Address for these; be explicit).
		if (isZero(b, 0, 10) && (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff) {
			return isGlobalIpv4(slice(b, 12));
		}
		// NAT64 well-known prefix 64:ff9b::/96: judged as the embedded IPv4 address.
		if ((b[0] & 0xff) == 0x00 && (b[1] & 0xff) == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b
				&& isZero(b, 4, 12)) {
			return isGlobalIpv4(slice(b, 12));
		}
		// Global unicast 2000::/3 only. This rejects ::/128, ::1, IPv4-compatible ::/96, IPv4-translated
		// ::ffff:0:0:0/96, local-use NAT64 64:ff9b:1::/48, discard-only 100::/64, ULA fc00::/7,
		// link-local fe80::/10, site-local fec0::/10 and multicast ff00::/8.
		if ((b[0] & 0xe0) != 0x20) {
			return false;
		}
		int w0 = ((b[0] & 0xff) << 8) | (b[1] & 0xff);
		int w1 = ((b[2] & 0xff) << 8) | (b[3] & 0xff);
		if (w0 == 0x2001 && w1 < 0x0200) { // 2001::/23 IETF protocol assignments, Teredo, ORCHID
			return false;
		}
		if (w0 == 0x2001 && w1 == 0x0db8) { // 2001:db8::/32 documentation
			return false;
		}
		if (w0 == 0x3fff && (w1 & 0xf000) == 0) { // 3fff::/20 documentation
			return false;
		}
		if (w0 == 0x2002) { // 6to4: the IPv4 address of the 6to4 site is in bits 16..47
			return isGlobalIpv4(new byte[] { b[2], b[3], b[4], b[5] });
		}
		return true;
	}

	private static boolean isZero(byte[] b, int from, int to) {
		for (int i = from; i < to; i++) {
			if (b[i] != 0) {
				return false;
			}
		}
		return true;
	}

	private static byte[] slice(byte[] b, int from) {
		return new byte[] { b[from], b[from + 1], b[from + 2], b[from + 3] };
	}

}

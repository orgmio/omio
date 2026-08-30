package handshake

import "crypto/fips140"

func withoutFIPSEnforcement(f func()) {
	fips140.WithoutEnforcement(f)
}

package cat

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"regexp"
)

var pathHashValidator = regexp.MustCompile("^[0-9a-f]{8}$")

// GeneratePathHash generates a path hash given a referring path hash,
// transaction name, and application name. referringPathHash can be an empty
// string if there was no referring path hash.
func GeneratePathHash(referringPathHash, txnName, appName string) (string, error) {
	var rph uint32
	if referringPathHash != "" {
		if !pathHashValidator.MatchString(referringPathHash) {
			// Per the spec, invalid referring path hashes should be treated as "0".
			referringPathHash = "0"
		}

		if _, err := fmt.Sscanf(referringPathHash, "%x", &rph); err != nil {
			fmt.Println(rph)
			return "", err
		}
		rph = (rph << 1) | (rph >> 31)
	}

	hashInput := fmt.Sprintf("%s;%s", appName, txnName)
	hash := md5.Sum([]byte(hashInput))
	low32 := binary.BigEndian.Uint32(hash[12:])

	return fmt.Sprintf("%08x", rph^low32), nil
}

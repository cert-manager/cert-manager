// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package alibabacloud

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPresent(t *testing.T) {

	provider, err := NewDNSProvider("access", "secret", "region")
	require.NoError(t, err)

	err = provider.Present("alibaba.example.com", "", "dns01-key")
	require.NoError(t, err)
}

func TestCleanUp(t *testing.T) {

	provider, err := NewDNSProvider("access", "secret", "region")
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = provider.CleanUp("alibaba.example.com", "", "dns01-key")
	require.NoError(t, err)
}

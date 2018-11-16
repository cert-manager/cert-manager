package memcached

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/rainycape/memcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/acme"
)

var (
	memcachedHosts []string
)

const (
	domain  = "lego.test"
	token   = "foo"
	keyAuth = "bar"
)

func init() {
	memcachedHostsStr := os.Getenv("MEMCACHED_HOSTS")
	if len(memcachedHostsStr) > 0 {
		memcachedHosts = strings.Split(memcachedHostsStr, ",")
	}
}

func TestNewMemcachedProviderEmpty(t *testing.T) {
	emptyHosts := make([]string, 0)
	_, err := NewMemcachedProvider(emptyHosts)
	assert.EqualError(t, err, "no memcached hosts provided")
}

func TestNewMemcachedProviderValid(t *testing.T) {
	if len(memcachedHosts) == 0 {
		t.Skip("Skipping memcached tests")
	}
	_, err := NewMemcachedProvider(memcachedHosts)
	require.NoError(t, err)
}

func TestMemcachedPresentSingleHost(t *testing.T) {
	if len(memcachedHosts) == 0 {
		t.Skip("Skipping memcached tests")
	}
	p, err := NewMemcachedProvider(memcachedHosts[0:1])
	require.NoError(t, err)

	challengePath := path.Join("/", acme.HTTP01ChallengePath(token))

	err = p.Present(domain, token, keyAuth)
	require.NoError(t, err)
	mc, err := memcache.New(memcachedHosts[0])
	require.NoError(t, err)
	i, err := mc.Get(challengePath)
	require.NoError(t, err)
	assert.Equal(t, i.Value, []byte(keyAuth))
}

func TestMemcachedPresentMultiHost(t *testing.T) {
	if len(memcachedHosts) <= 1 {
		t.Skip("Skipping memcached multi-host tests")
	}
	p, err := NewMemcachedProvider(memcachedHosts)
	require.NoError(t, err)

	challengePath := path.Join("/", acme.HTTP01ChallengePath(token))

	err = p.Present(domain, token, keyAuth)
	require.NoError(t, err)
	for _, host := range memcachedHosts {
		mc, err := memcache.New(host)
		require.NoError(t, err)
		i, err := mc.Get(challengePath)
		require.NoError(t, err)
		assert.Equal(t, i.Value, []byte(keyAuth))
	}
}

func TestMemcachedPresentPartialFailureMultiHost(t *testing.T) {
	if len(memcachedHosts) == 0 {
		t.Skip("Skipping memcached tests")
	}
	hosts := append(memcachedHosts, "5.5.5.5:11211")
	p, err := NewMemcachedProvider(hosts)
	require.NoError(t, err)

	challengePath := path.Join("/", acme.HTTP01ChallengePath(token))

	err = p.Present(domain, token, keyAuth)
	require.NoError(t, err)
	for _, host := range memcachedHosts {
		mc, err := memcache.New(host)
		require.NoError(t, err)
		i, err := mc.Get(challengePath)
		require.NoError(t, err)
		assert.Equal(t, i.Value, []byte(keyAuth))
	}
}

func TestMemcachedCleanup(t *testing.T) {
	if len(memcachedHosts) == 0 {
		t.Skip("Skipping memcached tests")
	}
	p, err := NewMemcachedProvider(memcachedHosts)
	require.NoError(t, err)
	require.NoError(t, p.CleanUp(domain, token, keyAuth))
}

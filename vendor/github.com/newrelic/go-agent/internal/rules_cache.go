package internal

import "sync"

// rulesCache is designed to avoid applying url-rules, txn-name-rules, and
// segment-rules since regexes are expensive!
type rulesCache struct {
	sync.RWMutex
	cache        map[rulesCacheKey]string
	maxCacheSize int
}

type rulesCacheKey struct {
	isWeb     bool
	inputName string
}

func newRulesCache(maxCacheSize int) *rulesCache {
	return &rulesCache{
		cache:        make(map[rulesCacheKey]string, maxCacheSize),
		maxCacheSize: maxCacheSize,
	}
}

func (cache *rulesCache) find(inputName string, isWeb bool) string {
	if nil == cache {
		return ""
	}
	cache.RLock()
	defer cache.RUnlock()

	return cache.cache[rulesCacheKey{
		inputName: inputName,
		isWeb:     isWeb,
	}]
}

func (cache *rulesCache) set(inputName string, isWeb bool, finalName string) {
	if nil == cache {
		return
	}
	cache.Lock()
	defer cache.Unlock()

	if len(cache.cache) >= cache.maxCacheSize {
		return
	}
	cache.cache[rulesCacheKey{
		inputName: inputName,
		isWeb:     isWeb,
	}] = finalName
}

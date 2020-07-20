package designate

func mergeMaps(src, dst map[string]string) map[string]string {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

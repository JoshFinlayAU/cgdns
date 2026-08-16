package resolver

import "context"

// refreshKey marks a query as a cache refresh rather than a client's question.
type refreshKey struct{}

// WithRefresh marks ctx as a cache refresh, which makes the resolver skip its
// own cache lookup for the name being asked about.
//
// Without it a refresh is a no-op: the entry it means to renew is still live,
// so the ordinary path answers from cache, never contacts the authoritative and
// never writes anything back. The entry then expires exactly as it would have
// without prefetching at all.
//
// It suppresses only the top-level lookup. Delegation and nameserver-address
// lookups still use the cache, because re-walking the whole chain from the root
// to refresh one leaf would cost far more than the refresh saves.
func WithRefresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, refreshKey{}, true)
}

// isRefresh reports whether ctx marks a cache refresh.
func isRefresh(ctx context.Context) bool {
	v, _ := ctx.Value(refreshKey{}).(bool)
	return v
}

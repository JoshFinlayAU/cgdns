package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	apipb "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GoBGP advertises and withdraws the anycast prefixes through a gobgpd running
// alongside this daemon.
//
// gobgpd is a separate process reached over its gRPC API — not the gobgp CLI,
// and not embedded in this binary. Shelling out to a CLI puts argument quoting
// on the failure path of a routing decision; embedding BGP means every restart
// of this daemon drops the session and blackholes the prefix until it comes
// back. A separate daemon keeps announcing across a resolver restart, and this
// package decides when it should stop.
type GoBGP struct {
	target   string
	prefixes []netip.Prefix
	log      *slog.Logger

	conn   *grpc.ClientConn
	client apipb.GoBgpServiceClient
}

// GoBGPOptions configures the advertiser.
type GoBGPOptions struct {
	// Target is gobgpd's gRPC address, conventionally 127.0.0.1:50051.
	Target string
	// Prefixes are the anycast routes this node originates.
	Prefixes []netip.Prefix
	// DialTimeout bounds the initial connection.
	DialTimeout time.Duration
	Log         *slog.Logger
}

// NewGoBGP connects to gobgpd.
func NewGoBGP(ctx context.Context, opts GoBGPOptions) (*GoBGP, error) {
	if opts.Target == "" {
		opts.Target = "127.0.0.1:50051"
	}
	if len(opts.Prefixes) == 0 {
		return nil, errors.New("health: at least one anycast prefix is required")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	// gobgpd listens on loopback, so plaintext is appropriate; the security
	// boundary is that nothing but this host can reach it.
	conn, err := grpc.NewClient(opts.Target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connecting to gobgpd at %s: %w", opts.Target, err)
	}

	g := &GoBGP{
		target:   opts.Target,
		prefixes: opts.Prefixes,
		log:      opts.Log,
		conn:     conn,
		client:   apipb.NewGoBgpServiceClient(conn),
	}

	probe, cancel := context.WithTimeout(ctx, opts.DialTimeout)
	defer cancel()
	if _, err := g.client.GetBgp(probe, &apipb.GetBgpRequest{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("gobgpd at %s did not answer: %w", opts.Target, err)
	}
	return g, nil
}

// Close releases the gRPC connection.
func (g *GoBGP) Close() error { return g.conn.Close() }

// Advertise originates every configured prefix.
func (g *GoBGP) Advertise(ctx context.Context) error {
	for _, p := range g.prefixes {
		path, err := pathFor(p)
		if err != nil {
			return err
		}
		if _, err := g.client.AddPath(ctx, &apipb.AddPathRequest{Path: path}); err != nil {
			return fmt.Errorf("advertising %s: %w", p, err)
		}
		g.log.Debug("advertised prefix", slog.String("prefix", p.String()))
	}
	return nil
}

// Withdraw removes every configured prefix.
//
// Errors are collected rather than returned on the first failure: a partial
// withdrawal is the worst outcome, so the remaining prefixes are still
// attempted.
func (g *GoBGP) Withdraw(ctx context.Context) error {
	var errs []error
	for _, p := range g.prefixes {
		path, err := pathFor(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := g.client.DeletePath(ctx, &apipb.DeletePathRequest{Path: path}); err != nil {
			errs = append(errs, fmt.Errorf("withdrawing %s: %w", p, err))
			continue
		}
		g.log.Debug("withdrew prefix", slog.String("prefix", p.String()))
	}
	return errors.Join(errs...)
}

// SessionsUp reports how many BGP sessions are established, for the operator
// API and as a signal that the node has somewhere to advertise to.
func (g *GoBGP) SessionsUp(ctx context.Context) (int, error) {
	stream, err := g.client.ListPeer(ctx, &apipb.ListPeerRequest{})
	if err != nil {
		return 0, fmt.Errorf("listing bgp peers: %w", err)
	}
	up := 0
	for {
		r, err := stream.Recv()
		if err != nil {
			break
		}
		if r.GetPeer().GetState().GetSessionState() == apipb.PeerState_SESSION_STATE_ESTABLISHED {
			up++
		}
	}
	return up, nil
}

// pathFor builds the gobgp path for a prefix, in the right address family.
func pathFor(p netip.Prefix) (*apipb.Path, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("invalid prefix %s", p)
	}

	family := &apipb.Family{Afi: apipb.Family_AFI_IP, Safi: apipb.Family_SAFI_UNICAST}
	nextHop := "0.0.0.0"
	if p.Addr().Is6() {
		family = &apipb.Family{Afi: apipb.Family_AFI_IP6, Safi: apipb.Family_SAFI_UNICAST}
		nextHop = "::"
	}

	return &apipb.Path{
		Family: family,
		Nlri: &apipb.NLRI{
			Nlri: &apipb.NLRI_Prefix{
				Prefix: &apipb.IPAddressPrefix{
					Prefix:    p.Addr().String(),
					PrefixLen: uint32(p.Bits()),
				},
			},
		},
		Pattrs: []*apipb.Attribute{
			// Origin IGP: the node is the origin of its own service prefix.
			{Attr: &apipb.Attribute_Origin{Origin: &apipb.OriginAttribute{Origin: 0}}},
			{Attr: &apipb.Attribute_NextHop{NextHop: &apipb.NextHopAttribute{NextHop: nextHop}}},
		},
	}, nil
}

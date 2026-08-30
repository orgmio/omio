package qlog

import (
	"context"

	"github.com/orgmio/quic-mio"
	"github.com/orgmio/quic-mio/qlog"
	"github.com/orgmio/quic-mio/qlogwriter"
)

const EventSchema = "urn:ietf:params:qlog:events:http3-12"

func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracerWithSchemas(ctx, isClient, connID, []string{qlog.EventSchema, EventSchema})
}

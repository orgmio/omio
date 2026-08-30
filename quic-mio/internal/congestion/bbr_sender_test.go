package congestion

import (
	"testing"
	"time"

	"github.com/orgmio/quic-mio/internal/monotime"
	"github.com/orgmio/quic-mio/internal/protocol"
	"github.com/orgmio/quic-mio/internal/utils"
)

type fakeClock struct{ t monotime.Time }

func (c *fakeClock) Now() monotime.Time { return c.t }

func TestBBRGrowsWindowFromDeliveryRate(t *testing.T) {
	clock := &fakeClock{t: monotime.Now()}
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(20*time.Millisecond, 0)
	sender := NewBBRSender(clock, rtt, &utils.ConnectionStats{}, 1200, nil)
	start := sender.GetCongestionWindow()

	now := clock.t
	var pn protocol.PacketNumber
	for round := 0; round < 8; round++ {
		for i := 0; i < 32; i++ {
			pn++
			sender.OnPacketSent(now, 0, pn, 1200, true)
		}
		now = now.Add(20 * time.Millisecond)
		clock.t = now
		for i := 0; i < 32; i++ {
			sender.OnPacketAcked(pn-protocol.PacketNumber(31-i), 1200, 32*1200, now)
		}
	}
	if got := sender.GetCongestionWindow(); got <= start {
		t.Fatalf("cwnd did not grow: start %d got %d", start, got)
	}
	if sender.BandwidthEstimate() == 0 {
		t.Fatal("expected a non-zero bandwidth estimate")
	}
}

func TestBBRDoesNotCutWindowOnLoss(t *testing.T) {
	clock := &fakeClock{t: monotime.Now()}
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(20*time.Millisecond, 0)
	sender := NewBBRSender(clock, rtt, &utils.ConnectionStats{}, 1200, nil)
	now := clock.t
	var pn protocol.PacketNumber
	for i := 0; i < 30; i++ {
		pn++
		sender.OnPacketSent(now, 0, pn, 1200, true)
		now = now.Add(20 * time.Millisecond)
		clock.t = now
		sender.OnPacketAcked(pn, 1200, 32*1200, now)
	}
	before := sender.GetCongestionWindow()
	sender.OnCongestionEvent(pn, 1200, before)
	if got := sender.GetCongestionWindow(); got < before {
		t.Fatalf("loss cut cwnd from %d to %d", before, got)
	}
}

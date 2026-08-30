package congestion

import (
	"fmt"
	"time"

	"github.com/orgmio/quic-mio/internal/monotime"
	"github.com/orgmio/quic-mio/internal/protocol"
	"github.com/orgmio/quic-mio/internal/utils"
	"github.com/orgmio/quic-mio/qlog"
	"github.com/orgmio/quic-mio/qlogwriter"
)

const (
	bbrMinCwndPackets     = 4
	bbrInitialCwndPackets = 32
	bbrMaxCwndPackets     = 64 * 1024
	bbrBandwidthSlots     = 10
	bbrStartupGrowth      = 1.25
	bbrStartupRounds      = 3
	bbrMinRTTExpire       = 10 * time.Second
	bbrInitialPacing      = 10 * BytesPerSecond * 1_000_000 / 8 // 10 Mbit/s
)

// bbrSender is a compact BBRv1-style controller.
// Delivery rate is estimated from ACKs; the congestion window is BDP*gain.
// Packet loss does not cut the window, which is why this survives the
// lossy long-haul paths where CUBIC collapses to a few Mbps.
type bbrSender struct {
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	pacer     *pacer
	clock     Clock

	maxDatagramSize protocol.ByteCount
	cwnd            protocol.ByteCount

	maxBandwidth Bandwidth
	bwSamples    [bbrBandwidthSlots]Bandwidth
	bwIndex      int
	bwFilled     int

	sampleStart  monotime.Time
	sampleBytes  protocol.ByteCount
	roundEnd     protocol.PacketNumber
	largestSent  protocol.PacketNumber
	largestAcked protocol.PacketNumber

	minRTT          time.Duration
	minRTTTimestamp monotime.Time

	startup            bool
	fullBandwidth      Bandwidth
	fullBandwidthCount int

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

// NewBBRSender creates a BBR congestion controller.
func NewBBRSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *bbrSender {
	if initialMaxDatagramSize == 0 {
		initialMaxDatagramSize = protocol.ByteCount(protocol.InitialPacketSize)
	}
	b := &bbrSender{
		rttStats:        rttStats,
		connStats:       connStats,
		clock:           clock,
		maxDatagramSize: initialMaxDatagramSize,
		cwnd:            bbrInitialCwndPackets * initialMaxDatagramSize,
		startup:         true,
		roundEnd:        protocol.InvalidPacketNumber,
		largestSent:     protocol.InvalidPacketNumber,
		largestAcked:    protocol.InvalidPacketNumber,
		qlogger:         qlogger,
	}
	b.pacer = newPacer(b.BandwidthEstimate)
	if b.qlogger != nil {
		b.lastState = qlog.CongestionStateSlowStart
		b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
	}
	return b
}

func (b *bbrSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) OnPacketSent(sentTime monotime.Time, _ protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	b.largestSent = packetNumber
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) MaybeExitSlowStart() {}

func (b *bbrSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, _ protocol.ByteCount, eventTime monotime.Time) {
	if number > b.largestAcked || b.largestAcked == protocol.InvalidPacketNumber {
		b.largestAcked = number
	}
	if b.roundEnd == protocol.InvalidPacketNumber || number > b.roundEnd {
		b.roundEnd = b.largestSent
		b.onRoundEnd()
	}
	b.updateMinRTT(eventTime)
	b.addBandwidthSample(ackedBytes, eventTime)
	b.updateWindow()
}

func (b *bbrSender) OnCongestionEvent(_ protocol.PacketNumber, lostBytes protocol.ByteCount, _ protocol.ByteCount) {
	if b.connStats != nil {
		b.connStats.PacketsLost.Add(1)
		b.connStats.BytesLost.Add(uint64(lostBytes))
	}
	// BBR does not cut cwnd on isolated loss. Startup still ends when
	// the delivery rate stops growing, which loss typically causes.
}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	b.startup = true
	b.fullBandwidth = 0
	b.fullBandwidthCount = 0
}

func (b *bbrSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	minBefore := b.minWindow()
	b.maxDatagramSize = s
	if b.cwnd == minBefore {
		b.cwnd = b.minWindow()
	}
	b.pacer.SetMaxDatagramSize(s)
}

func (b *bbrSender) InSlowStart() bool { return b.startup }
func (b *bbrSender) InRecovery() bool  { return false }

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	return b.cwnd
}

// BandwidthEstimate reports the current pacing bandwidth in bits/s.
func (b *bbrSender) BandwidthEstimate() Bandwidth {
	bw := b.maxFilter()
	if bw == 0 {
		bw = bbrInitialPacing
	}
	if b.startup {
		return bw * 2885 / 1000
	}
	return bw * 5 / 4
}

func (b *bbrSender) updateMinRTT(now monotime.Time) {
	sample := b.rttStats.MinRTT()
	if sample <= 0 {
		sample = b.rttStats.SmoothedRTT()
	}
	if sample <= 0 {
		return
	}
	if b.minRTT == 0 || sample < b.minRTT || now.Sub(b.minRTTTimestamp) > bbrMinRTTExpire {
		b.minRTT = sample
		b.minRTTTimestamp = now
	}
}

func (b *bbrSender) addBandwidthSample(acked protocol.ByteCount, now monotime.Time) {
	if b.sampleStart.IsZero() {
		b.sampleStart = now
		b.sampleBytes = acked
		return
	}
	b.sampleBytes += acked
	elapsed := now.Sub(b.sampleStart)
	minSample := b.minRTT
	if minSample <= 0 {
		minSample = b.rttStats.SmoothedRTT()
	}
	if minSample <= 0 {
		minSample = 10 * time.Millisecond
	}
	if elapsed < minSample {
		return
	}
	sample := BandwidthFromDelta(b.sampleBytes, elapsed)
	b.bwSamples[b.bwIndex] = sample
	b.bwIndex = (b.bwIndex + 1) % bbrBandwidthSlots
	if b.bwFilled < bbrBandwidthSlots {
		b.bwFilled++
	}
	if sample > b.maxBandwidth {
		b.maxBandwidth = sample
	}
	b.sampleStart = now
	b.sampleBytes = 0
}

func (b *bbrSender) onRoundEnd() {
	if !b.startup {
		return
	}
	bw := b.maxFilter()
	if bw == 0 {
		return
	}
	if b.fullBandwidth == 0 || bw >= Bandwidth(float64(b.fullBandwidth)*bbrStartupGrowth) {
		b.fullBandwidth = bw
		b.fullBandwidthCount = 0
		return
	}
	b.fullBandwidthCount++
	if b.fullBandwidthCount >= bbrStartupRounds {
		b.startup = false
		b.maybeQlog(qlog.CongestionStateCongestionAvoidance)
	}
}

func (b *bbrSender) updateWindow() {
	rtt := b.minRTT
	if rtt <= 0 {
		rtt = b.rttStats.SmoothedRTT()
	}
	if rtt <= 0 {
		rtt = 100 * time.Millisecond
	}
	bw := b.maxFilter()
	if bw == 0 {
		return
	}
	gain := 2.0
	if b.startup {
		gain = 2.885
	}
	bytesPerSec := float64(bw / BytesPerSecond)
	bdp := protocol.ByteCount(bytesPerSec * rtt.Seconds() * gain)
	computed := max(b.minWindow(), min(b.maxWindow(), bdp))
	if b.startup && computed < b.cwnd {
		// Sparse early ACK samples must not collapse the initial window.
		return
	}
	b.cwnd = computed
}

func (b *bbrSender) maxFilter() Bandwidth {
	var best Bandwidth
	for i := 0; i < b.bwFilled; i++ {
		if b.bwSamples[i] > best {
			best = b.bwSamples[i]
		}
	}
	if best == 0 {
		return b.maxBandwidth
	}
	return best
}

func (b *bbrSender) minWindow() protocol.ByteCount {
	return bbrMinCwndPackets * b.maxDatagramSize
}

func (b *bbrSender) maxWindow() protocol.ByteCount {
	return bbrMaxCwndPackets * b.maxDatagramSize
}

func (b *bbrSender) maybeQlog(state qlog.CongestionState) {
	if b.qlogger == nil || state == b.lastState {
		return
	}
	b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: state})
	b.lastState = state
}

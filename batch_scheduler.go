package neutrino

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type cfHeaderReqKey struct {
	pid  int32
	hash chainhash.Hash
}

type cfHeaderReqValue struct {
	qid int
	req *wire.MsgGetCFHeaders
}

type cfHeaderWriter func(*wire.MsgCFHeaders) (*chainhash.Hash, error)

type CFHeaderBatchHandler struct {
	genesisHeader chainhash.Hash
	curHeight     uint32
	curHeader     *chainhash.Hash
	initialHeader *chainhash.Hash
	checkpoints   []*chainhash.Hash

	mu         sync.Mutex
	queryMsgs  []wire.Message
	stopHashes map[chainhash.Hash]uint32
	trackers   map[cfHeaderReqKey]cfHeaderReqValue

	// We'll also create an additional set of maps that we'll use to
	// re-order the responses as we get them in.
	queryResponses map[uint32]*wire.MsgCFHeaders

	writeCFHeadersMsg cfHeaderWriter
}

func NewCFHeaderBatchHandler(
	genesisHeader *chainhash.Hash,
	curHeight uint32,
	curHeader *chainhash.Hash,
	checkpoints []*chainhash.Hash,
	queryMsgs []wire.Message,
	stopHashes map[chainhash.Hash]uint32,
	writer cfHeaderWriter) *CFHeaderBatchHandler {

	return &CFHeaderBatchHandler{
		genesisHeader:     *genesisHeader,
		curHeight:         curHeight,
		curHeader:         curHeader,
		initialHeader:     curHeader,
		checkpoints:       checkpoints,
		queryMsgs:         queryMsgs,
		stopHashes:        stopHashes,
		trackers:          make(map[cfHeaderReqKey]cfHeaderReqValue),
		queryResponses:    make(map[uint32]*wire.MsgCFHeaders),
		writeCFHeadersMsg: writer,
	}
}

func (h *CFHeaderBatchHandler) RegisterRequest(tracker BatchReqTracker) {
	req, ok := tracker.Request.(*wire.MsgGetCFHeaders)
	if !ok {
		return
	}

	trackerKey := cfHeaderReqKey{
		pid:  tracker.PeerID,
		hash: req.StopHash,
	}
	trackerVal := cfHeaderReqValue{
		qid: tracker.QueryID,
		req: req,
	}

	h.mu.Lock()
	h.trackers[trackerKey] = trackerVal
	h.mu.Unlock()
}

func (h *CFHeaderBatchHandler) RequestForResponse(
	pid int32, m wire.Message) (wire.Message, int, bool) {

	resp, ok := m.(*wire.MsgCFHeaders)
	if !ok {
		return nil, 0, false
	}

	trackerKey := cfHeaderReqKey{
		pid:  pid,
		hash: resp.StopHash,
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	trackerVal, ok := h.trackers[trackerKey]
	if !ok {
		return nil, 0, false
	}

	return trackerVal.req, trackerVal.qid, true
}

// queryState is an atomically updated per-query state for each query in a
// batch.
//
// State transitions are:
//
// * queryWaitSubmit->queryWaitResponse - send query to peer
// * queryWaitResponse->queryWaitSubmit - query timeout with no acceptable
//   response
// * queryWaitResponse->queryAnswered - acceptable response to query received
type queryState uint32

const (
	// Waiting to be submitted to a peer.
	queryWaitSubmit = uint32(iota)

	// Submitted to a peer, waiting for reply.
	queryWaitFastResponse

	queryWaitSlowResponse

	// Valid reply received.
	queryAnswered
)

type BatchReqTracker struct {
	PeerID  int32
	QueryID int
	Request wire.Message
}

type BatchPeer struct {
	*ServerPeer
	Quit chan struct{}
}

type batchPeerState struct {
	rtt time.Time

	taken       int
	inFlight    int
	maxInFlight int
	timedOut    int
	invalid     int
	successes   int
}

func makeBatchPeerState(initMaxInFlight int) batchPeerState {
	return batchPeerState{
		maxInFlight: initMaxInFlight,
	}
}

func (b *batchPeerState) percentSuccess() float64 {
	return float64(b.successes) / float64(b.taken-b.inFlight)
}

const (
	initialMaxPeerInFlight int = 50
	minPeerInFlight        int = 5
)

type BatchScheduler struct {
	firstUnfinished uint32   // used atomically
	lastUnfinished  uint32   // used atomically
	numFinished     uint32   // used atomically
	queryStates     []uint32 // used atomically
	numQueries      int

	peerMtx sync.RWMutex
	peers   map[int32]batchPeerState
}

func NewBatchScheduler(queries []wire.Message) *BatchScheduler {
	return &BatchScheduler{
		firstUnfinished: 0,
		lastUnfinished:  uint32(len(queries) - 1),
		numQueries:      len(queries),
		queryStates:     make([]uint32, len(queries)),
		peers:           make(map[int32]batchPeerState),
	}
}

func (s *BatchScheduler) Take(pid int32) (int, int, bool) {
	s.peerMtx.RLock()
	peerState, ok := s.peers[pid]
	if !ok {
		s.peerMtx.RUnlock()
		return s.getFU(), -1, false
	}
	isFastPeer := s.isFastPeer(pid, &peerState)
	s.peerMtx.RUnlock()

	// TODO(conner): add more granularity to peer bucketing

	switch {
	case isFastPeer:
		return s.scheduleFastPeer(pid, &peerState)
	default:
		return s.scheduleSlowPeer(pid, &peerState)
	}

}

func (s *BatchScheduler) scheduleFastPeer(
	pid int32, peerState *batchPeerState) (int, int, bool) {

	initialFirstUnfinished := s.getFU()
	initialLastUnfinished := s.getLU()

	firstUnfinished := initialFirstUnfinished
	updateFirstUnfinished := func() {
		if firstUnfinished != initialFirstUnfinished {
			s.setFU(firstUnfinished)
		}
	}

	for i := firstUnfinished; i <= initialLastUnfinished; i++ {
		if i == firstUnfinished && s.StatusIs(i, queryAnswered) {
			firstUnfinished++
			log.Tracef("Query #%v already answered, "+
				"skipping", i)
			continue
		}

		if peerState.inFlight >= peerState.maxInFlight {
			updateFirstUnfinished()
			return firstUnfinished, -1, true
		}

		if !s.transition(
			i, queryWaitSubmit, queryWaitFastResponse,
		) && !s.transition(
			i, queryWaitSlowResponse, queryWaitFastResponse,
		) {
			log.Tracef("Query #%v already being "+
				"queried for, skipping", i)
			continue
		}

		// Don't give to peer if slow.

		s.peerMtx.Lock()
		ps := s.peers[pid]

		ps.taken++
		ps.inFlight++

		s.peers[pid] = ps
		s.peerMtx.Unlock()

		updateFirstUnfinished()

		return firstUnfinished, i, true
	}

	updateFirstUnfinished()

	return firstUnfinished, -1, true
}

func (s *BatchScheduler) scheduleSlowPeer(
	pid int32, peerState *batchPeerState) (int, int, bool) {

	initialFirstUnfinished := s.getFU()
	initialLastUnfinished := s.getLU()

	lastUnfinished := initialLastUnfinished
	updateLastUnfinished := func() {
		if lastUnfinished != initialLastUnfinished {
			s.setLU(lastUnfinished)
		}
	}

	for i := lastUnfinished; i >= initialFirstUnfinished; i-- {
		if i == lastUnfinished && s.StatusIs(i, queryAnswered) {
			lastUnfinished--
			log.Tracef("Query #%v already answered, "+
				"skipping", i)
			continue
		}

		if peerState.inFlight >= peerState.maxInFlight {
			updateLastUnfinished()
			return s.getFU(), -1, false
		}

		if !s.transition(i, queryWaitSubmit, queryWaitSlowResponse) {
			log.Tracef("Query #%v already being "+
				"queried for, skipping", i)
			continue
		}

		// Don't give to peer if slow.

		s.peerMtx.Lock()
		ps := s.peers[pid]

		ps.taken++
		ps.inFlight++

		s.peers[pid] = ps
		s.peerMtx.Unlock()

		updateLastUnfinished()

		return s.getFU(), i, false
	}

	updateLastUnfinished()

	return s.getFU(), -1, false
}

func (s *BatchScheduler) AddBatchPeer(pid int32) {
	s.peerMtx.Lock()
	s.peers[pid] = makeBatchPeerState(initialMaxPeerInFlight)
	s.peerMtx.Unlock()
}

func (s *BatchScheduler) RemoveBatchPeer(pid int32) {
	s.peerMtx.Lock()
	delete(s.peers, pid)
	s.peerMtx.Unlock()
}

func (s *BatchScheduler) isFastPeer(pid int32, ps *batchPeerState) bool {
	if len(s.peers) == 1 {
		return true
	}

	var numBetterPeers int
	for peerID, peerState := range s.peers {
		if pid == peerID || peerState.maxInFlight < ps.maxInFlight {
			continue
		}

		numBetterPeers++
	}

	return numBetterPeers < len(s.peers)/2
}

func (s *BatchScheduler) StatusIs(i int, status uint32) bool {
	return atomic.LoadUint32(&s.queryStates[i]) == status
}

func (s *BatchScheduler) Success(pid int32, i int) {
	s.peerMtx.Lock()
	ps := s.peers[pid]

	ps.inFlight--
	ps.maxInFlight++
	ps.successes++

	s.peers[pid] = ps
	s.peerMtx.Unlock()

	s.setStatus(i, queryAnswered)
}

func (s *BatchScheduler) Timeout(pid int32, i int, isFast bool) {
	s.peerMtx.Lock()
	ps := s.peers[pid]

	ps.inFlight--
	ps.maxInFlight /= 2
	if ps.maxInFlight == 0 {
		ps.maxInFlight = minPeerInFlight
	}
	ps.timedOut++

	s.peers[pid] = ps
	s.peerMtx.Unlock()

	if isFast {
		s.transition(i, queryWaitFastResponse, queryWaitSubmit)
	} else {
		s.transition(i, queryWaitSlowResponse, queryWaitSubmit)
	}
}

func (s *BatchScheduler) Invalid(pid int32, i int) {
	s.peerMtx.Lock()
	ps := s.peers[pid]

	ps.inFlight--
	ps.maxInFlight = 0
	ps.invalid++

	s.peers[pid] = ps
	s.peerMtx.Unlock()

	if !s.transition(i, queryWaitSlowResponse, queryWaitSubmit) {
		s.transition(i, queryWaitFastResponse, queryWaitSubmit)
	}
}

func (s *BatchScheduler) setStatus(i int, status uint32) {
	atomic.StoreUint32(&s.queryStates[i], status)
}

func (s *BatchScheduler) transition(i int, to, from uint32) bool {
	return atomic.CompareAndSwapUint32(&s.queryStates[i], to, from)
}

func (s *BatchScheduler) getFU() int {
	return int(atomic.LoadUint32(&s.firstUnfinished))
}

func (s *BatchScheduler) setFU(i int) {
	atomic.StoreUint32(&s.firstUnfinished, uint32(i))
}

func (s *BatchScheduler) getLU() int {
	return int(atomic.LoadUint32(&s.lastUnfinished))
}

func (s *BatchScheduler) setLU(i int) {
	atomic.StoreUint32(&s.lastUnfinished, uint32(i))
}

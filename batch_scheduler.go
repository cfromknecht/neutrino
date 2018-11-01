package neutrino

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type BatchResponseHandler interface {
	Requests() []wire.Message
	RequestForResponse(int32, wire.Message) (wire.Message, int, bool)
	RegisterRequest(BatchReqTracker)
	CheckResponse(*ServerPeer, wire.Message, wire.Message) bool
}

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

	queryMsgs  []wire.Message
	stopHashes map[chainhash.Hash]uint32

	mu       sync.Mutex
	trackers map[cfHeaderReqKey]cfHeaderReqValue

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

func (h *CFHeaderBatchHandler) Requests() []wire.Message {
	return h.queryMsgs
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

func (h *CFHeaderBatchHandler) CheckResponse(
	sp *ServerPeer, query, resp wire.Message) bool {

	r, ok := resp.(*wire.MsgCFHeaders)
	if !ok {
		// We are only looking for cfheaders messages.
		return false
	}

	q, ok := query.(*wire.MsgGetCFHeaders)
	if !ok {
		// We sent a getcfheaders message, so that's
		// what we should be comparing against.
		return false
	}

	// The response doesn't match the query.
	if q.FilterType != r.FilterType ||
		q.StopHash != r.StopHash {
		return false
	}

	checkPointIndex, ok := h.stopHashes[r.StopHash]
	if !ok {
		// We never requested a matching stop hash.
		return false
	}

	// Use either the genesis header or the previous
	// checkpoint index as the previous checkpoint when
	// verifying that the filter headers in the response
	// match up.
	prevCheckpoint := &h.genesisHeader
	if checkPointIndex > 0 {
		prevCheckpoint = h.checkpoints[checkPointIndex-1]

	}
	nextCheckpoint := h.checkpoints[checkPointIndex]

	// The response doesn't match the checkpoint.
	if !verifyCheckpoint(prevCheckpoint, nextCheckpoint, r) {
		log.Warnf("Checkpoints at index %v don't match "+
			"response!!!", checkPointIndex)
		return false
	}

	// At this point, the response matches the query, and
	// the relevant checkpoint we got earlier, so we should
	// always return true so that the peer looking for the
	// answer to this query can move on to the next query.
	// We still have to check that these headers are next
	// before we write them; otherwise, we cache them if
	// they're too far ahead, or discard them if we don't
	// need them.

	// Find the first and last height for the blocks
	// represented by this message.
	startHeight := checkPointIndex*wire.CFCheckptInterval + 1
	lastHeight := (checkPointIndex + 1) * wire.CFCheckptInterval

	log.Debugf("Got cfheaders from height=%v to "+
		"height=%v, prev_hash=%v", startHeight,
		lastHeight, r.PrevFilterHeader)

	// If this is out of order but not yet written, we can
	// verify that the checkpoints match, and then store
	// them.
	if startHeight > h.curHeight+1 {
		log.Debugf("Got response for headers at "+
			"height=%v, only at height=%v, stashing",
			startHeight, h.curHeight)

		h.queryResponses[checkPointIndex] = r

		return true
	}

	// If this is out of order stuff that's already been
	// written, we can ignore it.
	if lastHeight <= h.curHeight {
		log.Debugf("Received out of order reply "+
			"end_height=%v, already written", lastHeight)
		return true
	}

	// If this is the very first range we've requested, we
	// may already have a portion of the headers written to
	// disk.
	//
	// TODO(roasbeef): can eventually special case handle
	// this at the top
	if bytes.Equal(h.curHeader[:], h.initialHeader[:]) {
		// So we'll set the prev header to our best
		// known header, and seek within the header
		// range a bit so we don't write any duplicate
		// headers.
		r.PrevFilterHeader = *h.curHeader
		offset := h.curHeight + 1 - startHeight
		r.FilterHashes = r.FilterHashes[offset:]
	}

	var err error
	h.curHeader, err = h.writeCFHeadersMsg(r)
	if err != nil {
		panic(fmt.Sprintf("couldn't write cfheaders "+
			"msg: %v", err))
	}

	// Then, we cycle through any cached messages, adding
	// them to the batch and deleting them from the cache.
	for {
		checkPointIndex++

		// We'll also update the current height of the
		// last written set of cfheaders.
		h.curHeight = checkPointIndex * wire.CFCheckptInterval

		// If we don't yet have the next response, then
		// we'll break out so we can wait for the peers
		// to respond with this message.
		r, ok := h.queryResponses[checkPointIndex]
		if !ok {
			break
		}

		// We have another response to write, so delete
		// it from the cache and write it.
		delete(h.queryResponses, checkPointIndex)

		log.Debugf("Writing cfheaders at height=%v to "+
			"next checkpoint", h.curHeight)

		// As we write the set of headers to disk, we
		// also obtain the hash of the last filter
		// header we've written to disk so we can
		// properly set the PrevFilterHeader field of
		// the next message.
		h.curHeader, err = h.writeCFHeadersMsg(r)
		if err != nil {
			panic(fmt.Sprintf("couldn't write "+
				"cfheaders msg: %v", err))
		}
	}

	return true

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
		fmt.Printf("querying for status %d\n", i)
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
	if _, ok := s.peers[pid]; !ok {
		s.peers[pid] = makeBatchPeerState(initialMaxPeerInFlight)
	}
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

/*
func (h *CFHeaderBatchHandler) CheckResponse(
	sp *ServerPeer, query, resp wire.Message) bool {

	r, ok := resp.(*wire.MsgCFHeaders)
	if !ok {
		// We are only looking for cfheaders messages.
		return false
	}

	q, ok := query.(*wire.MsgGetCFHeaders)
	if !ok {
		// We sent a getcfheaders message, so that's
		// what we should be comparing against.
		return false
	}

	// The response doesn't match the query.
	if q.FilterType != r.FilterType ||
		q.StopHash != r.StopHash {
		return false
	}

	checkPointIndex, ok := h.stopHashes[r.StopHash]
	if !ok {
		// We never requested a matching stop hash.
		return false
	}

	// The response doesn't match the checkpoint.
	if !verifyCheckpoint(h.checkpoints[checkPointIndex], r) {
		log.Warnf("Checkpoints at index %v don't match "+
			"response!!!", checkPointIndex)
		return false
	}

	// At this point, the response matches the query, and
	// the relevant checkpoint we got earlier, so we should
	// always return true so that the peer looking for the
	// answer to this query can move on to the next query.
	// We still have to check that these headers are next
	// before we write them; otherwise, we cache them if
	// they're too far ahead, or discard them if we don't
	// need them.

	// Find the first and last height for the blocks
	// represented by this message.
	startHeight := checkPointIndex*wire.CFCheckptInterval + 1
	lastHeight := startHeight + wire.CFCheckptInterval

	log.Debugf("Got cfheaders from height=%v to height=%v",
		startHeight, lastHeight)

	// If this is out of order but not yet written, we can
	// verify that the checkpoints match, and then store
	// them.
	if startHeight > h.curHeight+1 {
		log.Debugf("Got response for headers at "+
			"height=%v, only at height=%v, stashing",
			startHeight, h.curHeight)

		h.queryResponses[checkPointIndex] = r

		return true
	}

	// If this is out of order stuff that's already been
	// written, we can ignore it.
	if lastHeight <= h.curHeight {
		log.Debugf("Received out of order reply "+
			"end_height=%v, already written", lastHeight)
		return true
	}

	// If this is the very first range we've requested, we
	// may already have a portion of the headers written to
	// disk.
	//
	// TODO(roasbeef): can eventually special case handle
	// this at the top
	if bytes.Equal(h.curHeader[:], h.initialHeader[:]) {
		// So we'll set the prev header to our best
		// known header, and seek within the header
		// range a bit so we don't write any duplicate
		// headers.
		r.PrevFilterHeader = *h.curHeader
		offset := startHeight - h.curHeight - 1
		r.FilterHashes = r.FilterHashes[offset:]
	}

	var err error
	h.curHeader, err = h.writeCFHeadersMsg(r)
	if err != nil {
		panic(fmt.Sprintf("couldn't write cfheaders "+
			"msg: %v", err))
	}

	// Then, we cycle through any cached messages, adding
	// them to the batch and deleting them from the cache.
	for {
		checkPointIndex++

		// We'll also update the current height of the
		// last written set of cfheaders.
		h.curHeight = checkPointIndex * wire.CFCheckptInterval

		// If we don't yet have the next response, then
		// we'll break out so we can wait for the peers
		// to respond with this message.
		r := h.queryResponses[checkPointIndex]
		if r == nil {
			break
		}

		// We have another response to write, so delete
		// it from the cache and write it.
		h.queryResponses[checkPointIndex] = nil

		log.Debugf("Writing cfheaders at height=%v to "+
			"next checkpoint", h.curHeight)

		// As we write the set of headers to disk, we
		// also obtain the hash of the last filter
		// header we've written to disk so we can
		// properly set the PrevFilterHeader field of
		// the next message.
		h.curHeader, err = h.writeCFHeadersMsg(r)
		if err != nil {
			panic(fmt.Sprintf("couldn't write "+
				"cfheaders msg: %v", err))
		}
	}

	return true
}

// getCheckpointedCFHeaders catches a filter header store up with the
// checkpoints we got from the network. It assumes that the filter header store
// matches the checkpoints up to the tip of the store.
func (b *blockManager) getCheckpointedCFHeaders(checkpoints []*chainhash.Hash,
	store *headerfs.FilterHeaderStore, fType wire.FilterType) {

	// We keep going until we've caught up the filter header store with the
	// latest known checkpoint.
	curHeader, curHeight, err := store.ChainTip()
	if err != nil {
		panic("getting chaintip from store")
	}

	log.Infof("Fetching set of checkpointed cfheaders filters from "+
		"height=%v, hash=%v", curHeight, curHeader)

	// The starting interval is the checkpoint index that we'll be starting
	// from based on our current height in the filter header index.
	startingInterval := curHeight / wire.CFCheckptInterval

	log.Infof("Starting to query for cfheaders from "+
		"checkpoint_interval=%v", startingInterval)

	handler := NewCFHeaderBatchHandler(
		curHeight,
		curHeader,
		checkpoints,
		func(msg *wire.MsgCFHeaders) (*chainhash.Hash, error) {
			return b.writeCFHeadersMsg(msg, store)
		},
	)

	// Generate all of the requests we'll be batching and space to store
	// the responses. Also make a map of stophash to index to make it
	// easier to match against incoming responses.
	//
	// TODO(roasbeef): extract to func to test
	currentInterval := startingInterval
	for currentInterval < uint32(len(checkpoints)) {

		// Each checkpoint is spaced wire.CFCheckptInterval (1000
		// headers) after the prior one. We'll try and fetch headers
		// in batches twice that size, which is the largest allowed
		// response size.
		startHeightRange := uint32(
			currentInterval*wire.CFCheckptInterval,
		) + 1
		endHeightRange := uint32(
			(currentInterval + 1) * wire.CFCheckptInterval,
		)

		log.Tracef("Checkpointed cfheaders request start_range=%v, "+
			"end_range=%v", startHeightRange, endHeightRange)

		// In order to fetch the range, we'll need the block header for
		// the end of the height range.
		stopHeader, err := b.server.BlockHeaders.FetchHeaderByHeight(
			endHeightRange,
		)
		if err != nil {
			// Try to recover this.
			select {
			case <-b.quit:
				return
			default:
				currentInterval--
				time.Sleep(QueryTimeout)
				continue
			}
		}
		stopHash := stopHeader.BlockHash()

		// Once we have the stop hash, we can construct the query
		// message itself.
		queryMsg := wire.NewMsgGetCFHeaders(
			fType, uint32(startHeightRange), &stopHash,
		)

		// We'll mark that the ith interval is queried by this message,
		// and also map the top hash back to the index of this message.
		handler.queryMsgs = append(handler.queryMsgs, queryMsg)
		handler.stopHashes[stopHash] = currentInterval

		// With the queries for these two intervals constructed, we'll move
		// onto the next segments.
		currentInterval++
	}

	log.Infof("Attempting to query for %v cfheader batches",
		len(handler.queryMsgs))

	// With the set of messages constructed, we'll now request the batch
	// all at once. This message will distributed the header requests
	// amongst all active peers, effectively sharding each query
	// dynamically.
	b.server.queryBatch(handler.queryMsgs, handler, b.quit)
}
func (s *ChainService) queryBatch(
	// queryMsgs is a slice of queries for which the caller wants responses.
	queryMsgs []wire.Message,

	handler BatchRequestHandler,

	// queryQuit forces the query to end before it's complete.
	queryQuit <-chan struct{},

	// options takes functional options for executing the query.
	options ...QueryOption) {

	// Starting with the set of default options, we'll apply any specified
	// functional options to the query.
	qo := defaultQueryOptions()
	qo.applyQueryOptions(options...)

	scheduler := NewBatchScheduler(queryMsgs)

	type spBatchResp struct {
		sp   *ServerPeer
		req  wire.Message
		qid  int
		resp wire.Message
	}

	const numInFlight = 1000

	semas := make(chan struct{}, numInFlight)
	for i := 0; i < numInFlight; i++ {
		semas <- struct{}{}
	}

	// subscription allows us to subscribe to notifications from peers.
	respChan := make(chan spBatchResp, len(queryMsgs))

	var wg sync.WaitGroup

	peerReceiver := func(sp *ServerPeer, msgChan <-chan spMsg,
		timeouts map[int]*time.Timer, timeoutMtx *sync.Mutex, quit <-chan struct{}) {
		defer wg.Done()

		pid := sp.ID()

		for {
			var msg spMsg
			select {
			case <-queryQuit:
				return
			case <-quit:
				return
			case <-s.quit:
				return
			case msg = <-msgChan:
			}

			req, qid, ok := handler.RequestForResponse(pid, msg.msg)
			if !ok {
				log.Debugf("Received untracked %T response from peer %d", pid)
				continue
			}

			timeoutMtx.Lock()
			if timeouts == nil {
				timeoutMtx.Unlock()
				return
			}

			timer, ok := timeouts[qid]
			if !ok {
				timeoutMtx.Unlock()
				continue
			}

			if !timer.Stop() {
				timeoutMtx.Unlock()
				continue
			}

			delete(timeouts, qid)
			timeoutMtx.Unlock()

			if !scheduler.StatusIs(qid, queryWaitFastResponse) &&
				!scheduler.StatusIs(qid, queryWaitSlowResponse) {
				log.Debugf("Received LATE response from peer %d for query %d",
					pid, qid)
				continue
			}

			log.Debugf("Received response from peer %d for query %d",
				pid, qid)

			batchResp := spBatchResp{
				sp:   sp,
				req:  req,
				qid:  qid,
				resp: msg.msg,
			}

			select {
			case <-queryQuit:
				return
			case <-s.quit:
				return
			case <-quit:
				return
			case respChan <- batchResp:
			}
		}
	}

	peerRequester := func(sp *ServerPeer, sub spMsgSubscription,
		msgChan <-chan spMsg, quit <-chan struct{}) {
		defer wg.Done()

		var timeoutMtx sync.Mutex
		timeouts := make(map[int]*time.Timer)
		defer func() {
			timeoutMtx.Lock()
			for _, timer := range timeouts {
				timer.Stop()
			}
			timeouts = nil
			timeoutMtx.Unlock()
		}()

		// Subscribe to messages from the peer.
		sp.subscribeRecvMsg(sub)
		defer sp.unsubscribeRecvMsgs(sub)

		wg.Add(1)
		go peerReceiver(
			sp,
			msgChan,
			timeouts,
			&timeoutMtx,
			quit,
		)

		pid := sp.ID()

		// Track the last query our peer failed to answer and skip over
		// it for the next attempt. This helps prevent most instances
		// of the same peer being asked for the same query every time.
		firstUnfinished, nextQuery := 0, -1

		for firstUnfinished < len(queryMsgs) {
			var isFast bool
			firstUnfinished, nextQuery, isFast = scheduler.Take(pid)
			switch {
			case nextQuery == -1:
				if firstUnfinished == len(queryMsgs) {
					// We've now answered all the queries.
					return
				}

				// We have nothing to work on but not all
				// queries are answered yet. Wait for a query
				// timeout, or a quit signal, then see if
				// anything needs our help.
				select {
				case <-queryQuit:
					return
				case <-s.quit:
					return
				case <-quit:
					return
				case <-time.After(time.Second):
					if sp.Connected() {
						continue
					} else {
						return
					}
				}

			default:
			}

			cancel := func(qid int, fast bool) func() {
				return func() {
					timeoutMtx.Lock()
					if timeouts != nil {
						delete(timeouts, qid)
					}
					timeoutMtx.Unlock()

					// We failed, so set the query state
					// back to zero and update our
					// lastFailed state.
					scheduler.Timeout(sp.ID(), qid, fast)

					if !sp.Connected() {
						return
					}

					log.Debugf("Query for #%v failed, moving "+
						"on: %v", qid,
						newLogClosure(func() string {
							return spew.Sdump(
								queryMsgs[qid],
							)
						}))
				}
			}

			timeoutMtx.Lock()
			timeouts[nextQuery] = time.AfterFunc(
				qo.timeout, cancel(nextQuery, isFast),
			)
			timeoutMtx.Unlock()

			tracker := BatchReqTracker{
				PeerID:  sp.ID(),
				QueryID: nextQuery,
				Request: queryMsgs[nextQuery],
			}

			log.Debugf("Sending query #%v", nextQuery)

			handler.RegisterRequest(tracker)

			// The query is now marked as in-process. We
			// begin to process it.
			sp.QueueMessageWithEncoding(
				queryMsgs[nextQuery], nil, qo.encoding,
			)
		}
	}

	peerSubQuits := make(map[int32]chan struct{})

	// peerQuits holds per-peer quit channels so we can kill the goroutines
	// when they disconnect.
	peerQuits := make(map[int32]chan struct{})

	// Clean up on exit.
	defer wg.Wait()
	defer func() {
		for _, peerSubQuit := range peerSubQuits {
			close(peerSubQuit)
		}
		for _, quitChan := range peerQuits {
			close(quitChan)
		}
	}()

	ticker := time.NewTicker(qo.timeout)
	defer ticker.Stop()

	var firstUnfinished int
	for {
		// Update our view of peers, starting new workers for new peers
		// and removing disconnected/banned peers.
		for _, peer := range s.Peers() {
			pid := peer.ID()
			if _, ok := peerQuits[pid]; !ok && peer.Connected() {
				peerSubQuits[pid] = make(chan struct{})
				peerQuits[pid] = make(chan struct{})

				msgChan := make(chan spMsg, len(queryMsgs))
				peerSub := spMsgSubscription{
					msgChan:  msgChan,
					quitChan: peerSubQuits[pid],
				}

				scheduler.AddBatchPeer(pid)

				wg.Add(1)
				go peerRequester(
					peer, peerSub, msgChan, peerQuits[pid],
				)
			}

		}

		for pid, quitChan := range peerQuits {
			peer := s.PeerByID(pid)
			if peer == nil || !peer.Connected() {
				close(quitChan)
				delete(peerQuits, pid)
				close(peerSubQuits[pid])
				delete(peerSubQuits, pid)
				scheduler.RemoveBatchPeer(pid)
			}
		}

		select {
		case resp := <-respChan:
			if !handler.CheckResponse(
				resp.sp, resp.req, resp.resp,
			) {
				scheduler.Invalid(resp.sp.ID(), resp.qid)

				log.Debugf("Query #%v check failed",
					resp.qid)
				continue
			}

			// We got a match signal so we can mark this
			// query a success.
			scheduler.Success(resp.sp.ID(), resp.qid)

			log.Debugf("Query #%v answered, updating state",
				resp.qid)

		case <-ticker.C:
			// Check if we're done; if so, quit.
			allDone := true
			for i := firstUnfinished; i < len(queryMsgs); i++ {
				if !scheduler.StatusIs(i, queryAnswered) {
					allDone = false
					break
				}
				firstUnfinished++
			}
			if allDone {
				return
			}
		case <-queryQuit:
			return

		case <-s.quit:
			return
		}
	}
}
*/

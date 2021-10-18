// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

// Connection tracking is used to track and manipulate packets for NAT rules.
// The connection is created for a packet if it does not exist. Every
// connection contains two tuples (original and reply). The tuples are
// manipulated if there is a matching NAT rule. The packet is modified by
// looking at the tuples in each hook.
//
// Currently, only TCP tracking is supported.

// Our hash table has 16K buckets.
const numBuckets = 1 << 14

// Direction of the tuple.
type direction int

const (
	dirOriginal direction = iota
	dirReply
)

// Manipulation type for the connection.
// TODO(gvisor.dev/issue/5696): Define this as a bit set and support SNAT and
// DNAT at the same time.
type manipType int

const (
	manipNone manipType = iota
	manipSource
	manipDestination
)

// tuple holds a connection's identifying and manipulating data in one
// direction. It is immutable.
//
// +stateify savable
type tuple struct {
	// tupleEntry is used to build an intrusive list of tuples.
	tupleEntry

	tupleID

	// conn is the connection tracking entry this tuple belongs to.
	conn *conn

	// direction is the direction of the tuple.
	direction direction
}

// tupleID uniquely identifies a connection in one direction. It currently
// contains enough information to distinguish between any TCP or UDP
// connection, and will need to be extended to support other protocols.
//
// +stateify savable
type tupleID struct {
	srcAddr    tcpip.Address
	srcPort    uint16
	dstAddr    tcpip.Address
	dstPort    uint16
	transProto tcpip.TransportProtocolNumber
	netProto   tcpip.NetworkProtocolNumber
}

// reply creates the reply tupleID.
func (ti tupleID) reply() tupleID {
	return tupleID{
		srcAddr:    ti.dstAddr,
		srcPort:    ti.dstPort,
		dstAddr:    ti.srcAddr,
		dstPort:    ti.srcPort,
		transProto: ti.transProto,
		netProto:   ti.netProto,
	}
}

// conn is a tracked connection.
//
// +stateify savable
type conn struct {
	// original is the tuple in original direction. It is immutable.
	original tuple

	// reply is the tuple in reply direction. It is immutable.
	reply tuple

	// manip indicates if the packet should be manipulated. It is immutable.
	// TODO(gvisor.dev/issue/5696): Support updating manipulation type.
	manip manipType

	// tcbHook indicates if the packet is inbound or outbound to
	// update the state of tcb. It is immutable.
	tcbHook Hook

	// mu protects all mutable state.
	mu sync.Mutex `state:"nosave"`
	// tcb is TCB control block. It is used to keep track of states
	// of tcp connection and is protected by mu.
	tcb tcpconntrack.TCB
	// lastUsed is the last time the connection saw a relevant packet, and
	// is updated by each packet on the connection. It is protected by mu.
	//
	// TODO(gvisor.dev/issue/5939): do not use the ambient clock.
	lastUsed time.Time `state:".(unixTime)"`
}

// newConn creates new connection.
func newConn(orig, reply tupleID, manip manipType, hook Hook) *conn {
	conn := conn{
		manip:    manip,
		tcbHook:  hook,
		lastUsed: time.Now(),
	}
	conn.original = tuple{conn: &conn, tupleID: orig}
	conn.reply = tuple{conn: &conn, tupleID: reply, direction: dirReply}
	return &conn
}

// timedOut returns whether the connection timed out based on its state.
func (cn *conn) timedOut(now time.Time) bool {
	const establishedTimeout = 5 * 24 * time.Hour
	const defaultTimeout = 120 * time.Second
	cn.mu.Lock()
	defer cn.mu.Unlock()
	if cn.tcb.State() == tcpconntrack.ResultAlive {
		// Use the same default as Linux, which doesn't delete
		// established connections for 5(!) days.
		return now.Sub(cn.lastUsed) > establishedTimeout
	}
	// Use the same default as Linux, which lets connections in most states
	// other than established remain for <= 120 seconds.
	return now.Sub(cn.lastUsed) > defaultTimeout
}

// update the connection tracking state.
//
// +checklocks:cn.mu
func (cn *conn) updateLocked(pkt *PacketBuffer, reply bool) {
	if pkt.TransportProtocolNumber != header.TCPProtocolNumber {
		return
	}

	tcpHeader := header.TCP(pkt.TransportHeader().View())

	// Update the state of tcb. tcb assumes it's always initialized on the
	// client. However, we only need to know whether the connection is
	// established or not, so the client/server distinction isn't important.
	if cn.tcb.IsEmpty() {
		cn.tcb.Init(tcpHeader)
	} else if hook == cn.tcbHook {
		cn.tcb.UpdateStateOutbound(tcpHeader)
	} else {
		cn.tcb.UpdateStateInbound(tcpHeader)
	}
}

// ConnTrack tracks all connections created for NAT rules. Most users are
// expected to only call handlePacket, insertRedirectConn, and maybeInsertNoop.
//
// ConnTrack keeps all connections in a slice of buckets, each of which holds a
// linked list of tuples. This gives us some desirable properties:
// - Each bucket has its own lock, lessening lock contention.
// - The slice is large enough that lists stay short (<10 elements on average).
//   Thus traversal is fast.
// - During linked list traversal we reap expired connections. This amortizes
//   the cost of reaping them and makes reapUnused faster.
//
// Locks are ordered by their location in the buckets slice. That is, a
// goroutine that locks buckets[i] can only lock buckets[j] s.t. i < j.
//
// +stateify savable
type ConnTrack struct {
	// seed is a one-time random value initialized at stack startup
	// and is used in the calculation of hash keys for the list of buckets.
	// It is immutable.
	seed uint32

	// mu protects the buckets slice, but not buckets' contents. Only take
	// the write lock if you are modifying the slice or saving for S/R.
	mu sync.RWMutex `state:"nosave"`

	// buckets is protected by mu.
	buckets []bucket
}

// +stateify savable
type bucket struct {
	// mu protects tuples.
	mu     sync.Mutex `state:"nosave"`
	tuples tupleList
}

// packetToTupleID converts packet to a tuple ID. It fails when pkt lacks a valid
// TCP header.
//
// Preconditions: pkt.NetworkHeader() is valid.
func packetToTupleID(pkt *PacketBuffer) (tupleID, tcpip.Error) {
	netHeader := pkt.Network()
	if netHeader.TransportProtocol() != header.TCPProtocolNumber {
		return tupleID{}, &tcpip.ErrUnknownProtocol{}
	}

	tcpHeader := header.TCP(pkt.TransportHeader().View())
	if len(tcpHeader) < header.TCPMinimumSize {
		return tupleID{}, &tcpip.ErrUnknownProtocol{}
	}

	return tupleID{
		srcAddr:    netHeader.SourceAddress(),
		srcPort:    tcpHeader.SourcePort(),
		dstAddr:    netHeader.DestinationAddress(),
		dstPort:    tcpHeader.DestinationPort(),
		transProto: netHeader.TransportProtocol(),
		netProto:   pkt.NetworkProtocolNumber,
	}, nil
}

func (ct *ConnTrack) init() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.buckets = make([]bucket, numBuckets)
}

// connFor gets the conn for pkt if it exists, or returns nil
// if it does not. It returns an error when pkt does not contain a valid TCP
// header.
// TODO(gvisor.dev/issue/6168): Support UDP.
func (ct *ConnTrack) connFor(pkt *PacketBuffer) (*conn, direction) {
	tid, err := packetToTupleID(pkt)
	if err != nil {
		return nil, dirOriginal
	}
	return ct.connForTID(tid)
}

func (ct *ConnTrack) connForTID(tid tupleID) (*conn, direction) {
	bucket := ct.bucket(tid)
	now := time.Now()

	ct.mu.RLock()
	defer ct.mu.RUnlock()
	ct.buckets[bucket].mu.Lock()
	defer ct.buckets[bucket].mu.Unlock()

	// Iterate over the tuples in a bucket, cleaning up any unused
	// connections we find.
	for other := ct.buckets[bucket].tuples.Front(); other != nil; other = other.Next() {
		// Clean up any timed-out connections we happen to find.
		if ct.reapTupleLocked(other, bucket, now) {
			// The tuple expired.
			continue
		}
		if tid == other.tupleID {
			return other.conn, other.direction
		}
	}

	return nil, dirOriginal
}

func (ct *ConnTrack) insertRedirectConn(pkt *PacketBuffer, hook Hook, port uint16, address tcpip.Address) *conn {
	tid, err := packetToTupleID(pkt)
	if err != nil {
		return nil
	}
	if hook != Prerouting && hook != Output {
		return nil
	}

	replyTID := tid.reply()
	replyTID.srcAddr = address
	replyTID.srcPort = port

	conn, _ := ct.connForTID(tid)
	if conn != nil {
		// The connection is already tracked.
		// TODO(gvisor.dev/issue/5696): Support updating an existing connection.
		return nil
	}
	conn = newConn(tid, replyTID, manipDestination, hook)
	ct.insertConn(conn)
	return conn
}

func (ct *ConnTrack) insertSNATConn(pkt *PacketBuffer, hook Hook, port uint16, address tcpip.Address) *conn {
	tid, err := packetToTupleID(pkt)
	if err != nil {
		return nil
	}
	if hook != Input && hook != Postrouting {
		return nil
	}

	replyTID := tid.reply()
	replyTID.dstAddr = address
	replyTID.dstPort = port

	conn, _ := ct.connForTID(tid)
	if conn != nil {
		// The connection is already tracked.
		// TODO(gvisor.dev/issue/5696): Support updating an existing connection.
		return nil
	}
	conn = newConn(tid, replyTID, manipSource, hook)
	ct.insertConn(conn)
	return conn
}

// insertConn inserts conn into the appropriate table bucket.
func (ct *ConnTrack) insertConn(conn *conn) {
	// Lock the buckets in the correct order.
	tupleBucket := ct.bucket(conn.original.tupleID)
	replyBucket := ct.bucket(conn.reply.tupleID)
	ct.mu.RLock()
	bkt := &ct.buckets[bktID]
	ct.mu.RUnlock()

	now := time.Now()
	if t := bkt.connForTID(tid, now); t != nil {
		return t
	}

	bkt.mu.Lock()
	defer bkt.mu.Unlock()

	// Make sure a connection wasn't added between when we last checked the
	// bucket and acquired the bucket's write lock.
	if t := bkt.connForTIDRLocked(tid, now); t != nil {
		return t
	}

	// This is the first packet we're seeing for the connection. Create an entry
	// for this new connection.
	conn := &conn{
		ct:       ct,
		original: tuple{tupleID: tid},
		reply:    tuple{tupleID: tid.reply(), reply: true},
		lastUsed: now,
	}
	conn.original.conn = conn
	conn.reply.conn = conn

	// For now, we only map an entry for the packet's original tuple as NAT may be
	// performed on this connection. Until the packet goes through all the hooks
	// and its final address/port is known, we cannot know what the response
	// packet's addresses/ports will look like.
	//
	// This is okay because the destination cannot send its response until it
	// receives the packet; the packet will only be received once all the hooks
	// have been performed.
	//
	// See (*conn).finalize.
	bkt.tuples.PushFront(&conn.original)
	return &conn.original
}

func (ct *ConnTrack) connForTID(tid tupleID) *tuple {
	bktID := ct.bucket(tid)

	ct.mu.RLock()
	bkt := &ct.buckets[bktID]
	ct.mu.RUnlock()

	return bkt.connForTID(tid, time.Now())
}

func (bkt *bucket) connForTID(tid tupleID, now time.Time) *tuple {
	bkt.mu.RLock()
	defer bkt.mu.RUnlock()
	return bkt.connForTIDRLocked(tid, now)
}

// +checklocksread:bkt.mu
func (bkt *bucket) connForTIDRLocked(tid tupleID, now time.Time) *tuple {
	for other := bkt.tuples.Front(); other != nil; other = other.Next() {
		if tid == other.id() && !other.conn.timedOut(now) {
			return other
		}
	}
	return nil
}

func (ct *ConnTrack) finalize(cn *conn) {
	tid := cn.reply.id()
	id := ct.bucket(tid)

	ct.mu.RLock()
	bkt := &ct.buckets[id]
	ct.mu.RUnlock()

	bkt.mu.Lock()
	defer bkt.mu.Unlock()

	if t := bkt.connForTIDRLocked(tid, time.Now()); t != nil {
		// Another connection for the reply already exists. We can't do much about
		// this so we leave the connection cn represents in a state where it can
		// send packets but its responses will be mapped to some other connection.
		// This may be okay if the connection only expects to send packets without
		// any responses.
		return
	}

	bkt.tuples.PushFront(&cn.reply)
}

func (cn *conn) finalize() {
	{
		cn.mu.RLock()
		finalized := cn.finalized
		cn.mu.RUnlock()
		if finalized {
			return
		}
	}

	cn.mu.Lock()
	finalized := cn.finalized
	cn.finalized = true
	cn.mu.Unlock()
	if finalized {
		return
	}

	cn.ct.finalize(cn)
}

// performNAT setups up the connection for the specified NAT.
//
// Generally, only the first packet of a connection reaches this method; other
// other packets will be manipulated without needing to modify the connection.
func (cn *conn) performNAT(pkt *PacketBuffer, hook Hook, r *Route, port uint16, address tcpip.Address, dnat bool) {
	cn.performNATIfNoop(port, address, dnat)
	cn.handlePacket(pkt, hook, r)
}

func (cn *conn) performNATIfNoop(port uint16, address tcpip.Address, dnat bool) {
	cn.mu.Lock()
	defer cn.mu.Unlock()

	if cn.finalized {
		return
	}

	if dnat {
		if cn.destinationManip {
			return
		}
		cn.destinationManip = true
	} else {
		// Both tuples are in the same bucket.
		ct.buckets[tupleBucket].mu.Lock()
	}

	// Now that we hold the locks, ensure the tuple hasn't been inserted by
	// another thread.
	// TODO(gvisor.dev/issue/5773): Should check conn.reply.tupleID, too?
	alreadyInserted := false
	for other := ct.buckets[tupleBucket].tuples.Front(); other != nil; other = other.Next() {
		if other.tupleID == conn.original.tupleID {
			alreadyInserted = true
			break
		}
	}

	if !alreadyInserted {
		// Add the tuple to the map.
		ct.buckets[tupleBucket].tuples.PushFront(&conn.original)
		ct.buckets[replyBucket].tuples.PushFront(&conn.reply)
	}

	// Unlocking can happen in any order.
	ct.buckets[tupleBucket].mu.Unlock()
	if tupleBucket != replyBucket {
		ct.buckets[replyBucket].mu.Unlock() // +checklocksforce
	}
}

// handlePacket will manipulate the port and address of the packet if the
// connection exists. Returns whether, after the packet traverses the tables,
// it should create a new entry in the table.
func (ct *ConnTrack) handlePacket(pkt *PacketBuffer, hook Hook, r *Route) bool {
	if pkt.NatDone {
		return false
	}

	switch hook {
	case Prerouting, Input, Output, Postrouting:
	default:
		return false
	}

	// TODO(gvisor.dev/issue/6168): Support UDP.
	if pkt.Network().TransportProtocol() != header.TCPProtocolNumber {
		return false
	}

	conn, dir := ct.connFor(pkt)
	// Connection not found for the packet.
	if conn == nil {
		// If this is the last hook in the data path for this packet (Input if
		// incoming, Postrouting if outgoing), indicate that a connection should be
		// inserted by the end of this hook.
		return hook == Input || hook == Postrouting
	}

	netHeader := pkt.Network()
	tcpHeader := header.TCP(pkt.TransportHeader().View())
	if len(tcpHeader) < header.TCPMinimumSize {
		return false
	}

	// TODO(gvisor.dev/issue/5748): TCP checksums on inbound packets should be
	// validated if checksum offloading is off. It may require IP defrag if the
	// packets are fragmented.

	var newAddr tcpip.Address
	var newPort uint16

	updateSRCFields := false

	switch hook {
	case Prerouting, Output:
		if conn.manip == manipDestination {
			switch dir {
			case dirOriginal:
				newPort = conn.reply.srcPort
				newAddr = conn.reply.srcAddr
			case dirReply:
				newPort = conn.original.dstPort
				newAddr = conn.original.dstAddr

				updateSRCFields = true
			}
			pkt.NatDone = true
		}
	case Input, Postrouting:
		if conn.manip == manipSource {
			switch dir {
			case dirOriginal:
				newPort = conn.reply.dstPort
				newAddr = conn.reply.dstAddr

				updateSRCFields = true
			case dirReply:
				newPort = conn.original.srcPort
				newAddr = conn.original.srcAddr
			}
			pkt.NatDone = true
		}
	default:
		panic(fmt.Sprintf("unrecognized hook = %s", hook))
	}
	if !pkt.NatDone {
		return false
	}

	fullChecksum := false
	updatePseudoHeader := false
	switch hook {
	case Prerouting, Input:
	case Output, Postrouting:
		// Calculate the TCP checksum and set it.
		if pkt.GSOOptions.Type != GSONone && pkt.GSOOptions.NeedsCsum {
			updatePseudoHeader = true
		} else if r.RequiresTXTransportChecksum() {
			fullChecksum = true
			updatePseudoHeader = true
		}
	default:
		panic(fmt.Sprintf("unrecognized hook = %s", hook))
	}

	rewritePacket(
		netHeader,
		tcpHeader,
		updateSRCFields,
		fullChecksum,
		updatePseudoHeader,
		newPort,
		newAddr,
	)

	// Update the state of tcb.
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Mark the connection as having been used recently so it isn't reaped.
	conn.lastUsed = time.Now()
	// Update connection state.
	conn.updateLocked(header.TCP(pkt.TransportHeader().View()), hook)

	return false
}

// maybeInsertNoop tries to insert a no-op connection entry to keep connections
// from getting clobbered when replies arrive. It only inserts if there isn't
// already a connection for pkt.
//
// This should be called after traversing iptables rules only, to ensure that
// pkt.NatDone is set correctly.
func (ct *ConnTrack) maybeInsertNoop(pkt *PacketBuffer, hook Hook) {
	// If there were a rule applying to this packet, it would be marked
	// with NatDone.
	if pkt.NatDone {
		return
	}

	// We only track TCP connections.
	if pkt.Network().TransportProtocol() != header.TCPProtocolNumber {
		return
	}

	// This is the first packet we're seeing for the TCP connection. Insert
	// the noop entry (an identity mapping) so that the response doesn't
	// get NATed, breaking the connection.
	tid, err := packetToTupleID(pkt)
	if err != nil {
		return
	}
	conn := newConn(tid, tid.reply(), manipNone, hook)
	conn.updateLocked(header.TCP(pkt.TransportHeader().View()), hook)
	ct.insertConn(conn)
}

// bucket gets the conntrack bucket for a tupleID.
func (ct *ConnTrack) bucket(id tupleID) int {
	h := jenkins.Sum32(ct.seed)
	h.Write([]byte(id.srcAddr))
	h.Write([]byte(id.dstAddr))
	shortBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(shortBuf, id.srcPort)
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, id.dstPort)
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, uint16(id.transProto))
	h.Write([]byte(shortBuf))
	binary.LittleEndian.PutUint16(shortBuf, uint16(id.netProto))
	h.Write([]byte(shortBuf))
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return int(h.Sum32()) % len(ct.buckets)
}

// reapUnused deletes timed out entries from the conntrack map. The rules for
// reaping are:
// - Most reaping occurs in connFor, which is called on each packet. connFor
//   cleans up the bucket the packet's connection maps to. Thus calls to
//   reapUnused should be fast.
// - Each call to reapUnused traverses a fraction of the conntrack table.
//   Specifically, it traverses len(ct.buckets)/fractionPerReaping.
// - After reaping, reapUnused decides when it should next run based on the
//   ratio of expired connections to examined connections. If the ratio is
//   greater than maxExpiredPct, it schedules the next run quickly. Otherwise it
//   slightly increases the interval between runs.
// - maxFullTraversal caps the time it takes to traverse the entire table.
//
// reapUnused returns the next bucket that should be checked and the time after
// which it should be called again.
func (ct *ConnTrack) reapUnused(start int, prevInterval time.Duration) (int, time.Duration) {
	const fractionPerReaping = 128
	const maxExpiredPct = 50
	const maxFullTraversal = 60 * time.Second
	const minInterval = 10 * time.Millisecond
	const maxInterval = maxFullTraversal / fractionPerReaping

	now := time.Now()
	checked := 0
	expired := 0
	var idx int
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	for i := 0; i < len(ct.buckets)/fractionPerReaping; i++ {
		idx = (i + start) % len(ct.buckets)
		ct.buckets[idx].mu.Lock()
		for tuple := ct.buckets[idx].tuples.Front(); tuple != nil; tuple = tuple.Next() {
			checked++
			if ct.reapTupleLocked(tuple, idx, now) {
				expired++
			}
		}
		ct.buckets[idx].mu.Unlock()
	}
	// We already checked buckets[idx].
	idx++

	// If half or more of the connections are expired, the table has gotten
	// stale. Reschedule quickly.
	expiredPct := 0
	if checked != 0 {
		expiredPct = expired * 100 / checked
	}
	if expiredPct > maxExpiredPct {
		return idx, minInterval
	}
	if interval := prevInterval + minInterval; interval <= maxInterval {
		// Increment the interval between runs.
		return idx, interval
	}
	// We've hit the maximum interval.
	return idx, maxInterval
}

// reapTupleLocked tries to remove tuple and its reply from the table. It
// returns whether the tuple's connection has timed out.
//
// Precondition: ct.mu is read locked and bkt.mu is write locked.
// +checklocksread:ct.mu
// +checklocks:bkt.mu
func (ct *ConnTrack) reapTupleLocked(tuple *tuple, bktID int, bkt *bucket, now time.Time) bool {
	if !tuple.conn.timedOut(now) {
		return false
	}

	// To maintain lock order, we can only reap these tuples if the reply
	// appears later in the table.
	replyBucket := ct.bucket(tuple.reply())
	if bucket > replyBucket {
		return true
	}

	// Don't re-lock if both tuples are in the same bucket.
	differentBuckets := bucket != replyBucket
	if differentBuckets {
		ct.buckets[replyBucket].mu.Lock()
	}

	// We have the buckets locked and can remove both tuples.
	if tuple.direction == dirOriginal {
		ct.buckets[replyBucket].tuples.Remove(&tuple.conn.reply)
	} else {
		ct.buckets[replyBucket].tuples.Remove(&tuple.conn.original)
	}
	ct.buckets[bucket].tuples.Remove(tuple)

	// Don't re-unlock if both tuples are in the same bucket.
	if differentBuckets {
		ct.buckets[replyBucket].mu.Unlock() // +checklocksforce
	}

	return true
}

// +checklocks:b.mu
func removeConnFromBucket(b *bucket, tuple *tuple) {
	if tuple.reply {
		b.tuples.Remove(&tuple.conn.original)
	} else {
		b.tuples.Remove(&tuple.conn.reply)
	}
}

func (ct *ConnTrack) originalDst(epID TransportEndpointID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber) (tcpip.Address, uint16, tcpip.Error) {
	// Lookup the connection. The reply's original destination
	// describes the original address.
	tid := tupleID{
		srcAddr:    epID.LocalAddress,
		srcPort:    epID.LocalPort,
		dstAddr:    epID.RemoteAddress,
		dstPort:    epID.RemotePort,
		transProto: header.TCPProtocolNumber,
		netProto:   netProto,
	}
	conn, _ := ct.connForTID(tid)
	if conn == nil {
		// Not a tracked connection.
		return "", 0, &tcpip.ErrNotConnected{}
	} else if conn.manip != manipDestination {
		// Unmanipulated destination.
		return "", 0, &tcpip.ErrInvalidOptionValue{}
	}

	return conn.original.dstAddr, conn.original.dstPort, nil
}

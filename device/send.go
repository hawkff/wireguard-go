/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	buffer []byte // sing-allocated buffer holding the packet data
	// packet is always a slice of "buffer". The starting offset in buffer
	// is either:
	//  a) MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize (plaintext)
	//  b) 0 (post-encryption)
	packet      []byte
	nonce       uint64   // nonce for encryption
	keypair     *Keypair // keypair for encryption
	peer        *Peer    // related peer
	padding     uint32
	isKeepalive bool
}

type QueueOutboundElementsContainer struct {
	// filling is a one-shot barrier signaling encryption→send handoff.
	// SendStagedPackets calls Add(1) before sending the container down
	// the encryption and outbound queues; RoutineEncryption calls Done
	// after encrypting; RoutineSequentialSender calls Wait before
	// reading the encrypted packets.
	filling sync.WaitGroup
	elems   []*QueueOutboundElement
	awg     *awgConfig
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(MaxMessageSize)
	elem.nonce = 0
	elem.padding = device.getAWGConfig().paddings.transport
	elem.isKeepalive = false
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
	elem.isKeepalive = false
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		awg := peer.device.getAWGConfig()
		elem := peer.device.NewOutboundElement()
		elem.padding = awg.paddings.transport
		elem.isKeepalive = true
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.awg = awg
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.queuedOutboundPackets.Add(1)
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets()
}

// SendPriorityMessage invokes the [PeerPriorityMessageFunc] callback if one is
// set, and queues the returned message for encryption and transmission if the
// current keypair is valid.
func (peer *Peer) SendPriorityMessage() {
	f := peer.device.priorityMsgFn.Load()
	if f == nil {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || sinceIncludingSleep(keypair.created) >= peer.device.keychainExpireTime() {
		// SendStagedPackets initializes a handshake when the keypair is invalid,
		// but we explicitly avoid that here. A priority message is only intended
		// to flow around symmetric session establishment, but it should never
		// trigger a new session. Reaching this branch due to nonce exhaustion
		// or keypair expiration is highly unlikely considering where
		// SendPriorityMessage is called (at current keypair establishment).
		return
	}

	// get plaintext message to send
	msg := (*f)(peer.handshake.remoteStatic)
	if len(msg) == 0 {
		return
	}
	if len(msg) > MaxPriorityMessageContentSize {
		peer.device.log.Verbosef("%v - Failed to queue priority message due to size", peer)
		return
	}

	awg := peer.device.getAWGConfig()
	padding := awg.paddings.transport
	offset := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize
	if len(msg)+chacha20poly1305.Overhead > MaxMessageSize-offset {
		peer.device.log.Verbosef("%v - Failed to queue priority message due to AWG transport padding", peer)
		return
	}

	// get pooled elements
	elem := peer.device.NewOutboundElement()
	elem.padding = padding
	elemsContainer := peer.device.GetOutboundElementsContainer()
	elemsContainer.awg = awg
	elemsContainer.elems = append(elemsContainer.elems, elem)
	packetQueued := false
	defer func() {
		if !packetQueued {
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}()

	// initialize outbound element
	n := copy(elem.buffer[offset:], msg)
	elem.packet = elem.buffer[offset : offset+n]
	elem.peer = peer
	elem.nonce = keypair.sendNonce.Add(1) - 1
	if elem.nonce >= RejectAfterMessages {
		keypair.sendNonce.Store(RejectAfterMessages)
		return
	}
	elem.keypair = keypair

	// add to parallel and sequential queue
	if peer.isRunning.Load() {
		elemsContainer.filling.Add(1)
		peer.queuedOutboundPackets.Add(1)
		peer.queue.outbound.c <- elemsContainer
		peer.device.queue.encryption.c <- elemsContainer
		packetQueued = true
	}
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
		peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttemps())
	}

	timeout := peer.device.rekeyMinTimeout()

	peer.handshake.mutex.RLock()
	if sinceIncludingSleep(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if sinceIncludingSleep(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	candidates := peer.resolveEndpoints()

	awg := peer.device.getAWGConfig()
	msg, err := peer.device.createMessageInitiation(peer, awg)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	var sendBuffer [][]byte
	for _, ipacket := range awg.ipackets {
		if ipacket == nil {
			continue
		}
		buf := make([]byte, MessageEncapsulatingTransportSize+ipacket.ObfuscatedLen(0))
		ipacket.Obfuscate(buf[MessageEncapsulatingTransportSize:], nil)
		sendBuffer = append(sendBuffer, buf)
	}

	jc := awg.junk.count
	jmin := awg.junk.min
	jmax := awg.junk.max
	if jc > 0 && jmax >= jmin {
		for range jc {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(jmax-jmin+1)))
			n := int(nBig.Int64()) + int(jmin)
			buf := make([]byte, MessageEncapsulatingTransportSize+n)
			rand.Read(buf[MessageEncapsulatingTransportSize:])
			sendBuffer = append(sendBuffer, buf)
		}
	}

	padding := int(awg.paddings.init)
	trailerLen := max(peer.randomTrailer(padding+MessageInitiationSize, awg), 0)
	buf := make([]byte, MessageEncapsulatingTransportSize+padding+MessageInitiationSize+trailerLen)
	crypt := buf[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+padding]
	rand.Read(crypt)
	messageStart := MessageEncapsulatingTransportSize + padding
	packet := buf[messageStart : messageStart+MessageInitiationSize]
	_ = msg.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)
	sendBuffer = append(sendBuffer, buf)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := awg.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	trailer := buf[messageStart+MessageInitiationSize:]
	rand.Read(trailer)
	if len(candidates) > 0 {
		err = peer.sendHandshakeBuffers(sendBuffer, candidates)
	} else {
		err = peer.SendBuffers(sendBuffer)
	}
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	awg := peer.device.getAWGConfig()
	response, err := peer.device.createMessageResponse(peer, awg)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	padding := int(awg.paddings.response)
	trailerLen := max(peer.randomTrailer(padding+MessageResponseSize, awg), 0)
	buf := make([]byte, MessageEncapsulatingTransportSize+padding+MessageResponseSize+trailerLen)
	crypt := buf[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+padding]
	rand.Read(crypt)
	messageStart := MessageEncapsulatingTransportSize + padding
	packet := buf[messageStart : messageStart+MessageResponseSize]
	_ = response.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := awg.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	trailer := buf[messageStart+MessageResponseSize:]
	rand.Read(trailer)
	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{buf})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	awg := device.getAWGConfig()

	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := device.cookieChecker.CreateReply(
		initiatingElem.packet,
		sender,
		initiatingElem.endpoint.DstToBytes(),
		awg.headers.cookie.PickOne(),
	)
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	padding := int(awg.paddings.cookie)
	trailerLen := max(device.randomTrailer(padding+MessageCookieReplySize, awg), 0)
	buf := make([]byte, MessageEncapsulatingTransportSize+padding+MessageCookieReplySize+trailerLen)
	crypt := buf[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+padding]
	rand.Read(crypt)
	messageStart := MessageEncapsulatingTransportSize + padding
	packet := buf[messageStart : messageStart+MessageCookieReplySize]
	_ = reply.marshal(packet)

	cip, err := awg.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	trailer := buf[messageStart+MessageCookieReplySize:]
	rand.Read(trailer)
	// TODO: allocation could be avoided
	return device.net.bind.Send([][]byte{buf}, initiatingElem.endpoint, MessageEncapsulatingTransportSize)
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && sinceIncludingSleep(keypair.created) > peer.device.keyRefreshTimeoutSending()) {
		peer.SendHandshakeInitiation(false)
	}
}

func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	var (
		batchSize   = device.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
		sizes       = make([]int, batchSize)
	)

	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutOutboundBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	for {
		awg := device.getAWGConfig()
		padding := awg.paddings.transport
		offset := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize
		for _, elem := range elems {
			elem.padding = padding
		}

		// read packets
		count, readErr = device.tun.device.Read(bufs, sizes, offset)
		sendAWG := device.getAWGConfig()
		sendPadding := sendAWG.paddings.transport
		sendOffset := MessageEncapsulatingTransportSize + int(sendPadding) + MessageTransportHeaderSize
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			if sendOffset+sizes[i]+chacha20poly1305.Overhead > len(bufs[i]) {
				device.log.Verbosef("Dropped outbound packet: AWG transport padding exceeds buffer capacity")
				continue
			}
			if sendOffset != offset {
				copy(bufs[i][sendOffset:sendOffset+sizes[i]], bufs[i][offset:offset+sizes[i]])
			}
			elem.packet = bufs[i][sendOffset : sendOffset+sizes[i]]
			elem.padding = sendPadding

			// lookup peer
			var peer *Peer
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				src := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]))
				dst := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				src := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]))
				dst := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			default:
				device.log.Verbosef("Received packet with unknown IP version")
			}

			if peer == nil {
				continue
			}
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsForPeer.awg = sendAWG
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(elemsForPeer)
				peer.SendStagedPackets()
			} else {
				for _, elem := range elemsForPeer.elems {
					device.PutOutboundBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

// maxQueuedInputPackets bounds the staged+outbound backlog of a peer fed via
// InputPacket/InputPackets. Injected packets beyond it are dropped before they
// are copied into pooled message buffers, like a full qdisc: injection has no
// flow control, and the queues are bounded in containers (up to a full batch
// each), so without this cap a flood is buffered instead of dropped.
const maxQueuedInputPackets = 2048

func (device *Device) inputPacketPeer(destination []byte, packetSlices [][]byte) *Peer {
	var src, dst netip.Addr
	switch len(destination) {
	case net.IPv4len:
		dst = netip.AddrFrom4([4]byte(destination))
		var srcBytes [net.IPv4len]byte
		if !gatherPacketBytes(packetSlices, IPv4offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom4(srcBytes)
	case net.IPv6len:
		dst = netip.AddrFrom16([16]byte(destination))
		var srcBytes [net.IPv6len]byte
		if !gatherPacketBytes(packetSlices, IPv6offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom16(srcBytes)
	default:
		return nil
	}
	var ipPkt []byte
	if len(packetSlices) == 1 {
		ipPkt = packetSlices[0]
	}
	return device.allowedips.LookupFromPacket(src, dst, ipPkt)
}

func gatherPacketBytes(packetSlices [][]byte, offset int, destination []byte) bool {
	for _, packetSlice := range packetSlices {
		if offset >= len(packetSlice) {
			offset -= len(packetSlice)
			continue
		}
		n := copy(destination, packetSlice[offset:])
		destination = destination[n:]
		offset = 0
		if len(destination) == 0 {
			return true
		}
	}
	return false
}

func (device *Device) InputPacket(destination []byte, packetSlices [][]byte) {
	peer := device.inputPacketPeer(destination, packetSlices)
	if peer == nil {
		return
	}
	if peer.queuedOutboundPackets.Load() >= maxQueuedInputPackets {
		return
	}
	var totalLength int
	for _, packetSlice := range packetSlices {
		totalLength += len(packetSlice)
	}
	allocLength := MessageEncapsulatingTransportSize + MessageTransportHeaderSize + totalLength + PaddingMultiple + chacha20poly1305.Overhead
	if allocLength > MaxMessageSize {
		return
	}
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(allocLength)
	elem.nonce = 0
	packet := elem.buffer[MessageEncapsulatingTransportSize+MessageTransportHeaderSize:]
	var n int
	for _, packetSlice := range packetSlices {
		n += copy(packet[n:], packetSlice)
	}
	elem.packet = packet[:n]
	elemsForPeer := device.GetOutboundElementsContainer()
	if peer.isRunning.Load() {
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
		peer.StagePackets(elemsForPeer)
		peer.SendStagedPackets()
	} else {
		device.PutOutboundBuffer(elem.buffer)
		device.PutOutboundElement(elem)
		device.PutOutboundElementsContainer(elemsForPeer)
	}
}

type InputPacketRef struct {
	Destination  []byte
	PacketSlices [][]byte
}

func (device *Device) InputPackets(packets []*InputPacketRef) []*InputPacketRef {
	var unmatched []*InputPacketRef
	elemsByPeer := make(map[*Peer][]*QueueOutboundElementsContainer, len(packets))
	for _, packetRef := range packets {
		peer := device.inputPacketPeer(packetRef.Destination, packetRef.PacketSlices)
		if peer == nil {
			unmatched = append(unmatched, packetRef)
			continue
		}
		if peer.queuedOutboundPackets.Load() >= maxQueuedInputPackets {
			continue
		}
		var totalLength int
		for _, packetSlice := range packetRef.PacketSlices {
			totalLength += len(packetSlice)
		}
		allocLength := MessageEncapsulatingTransportSize + MessageTransportHeaderSize + totalLength + PaddingMultiple + chacha20poly1305.Overhead
		if allocLength > MaxMessageSize {
			continue
		}
		elem := device.GetOutboundElement()
		elem.buffer = device.GetOutboundBuffer(allocLength)
		elem.nonce = 0
		packet := elem.buffer[MessageEncapsulatingTransportSize+MessageTransportHeaderSize:]
		var n int
		for _, packetSlice := range packetRef.PacketSlices {
			n += copy(packet[n:], packetSlice)
		}
		elem.packet = packet[:n]
		containers := elemsByPeer[peer]
		if len(containers) == 0 || len(containers[len(containers)-1].elems) >= conn.IdealBatchSize {
			containers = append(containers, device.GetOutboundElementsContainer())
			elemsByPeer[peer] = containers
		}
		elemsForPeer := containers[len(containers)-1]
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
	}
	for peer, containers := range elemsByPeer {
		if peer.isRunning.Load() {
			for _, elemsForPeer := range containers {
				peer.StagePackets(elemsForPeer)
			}
			peer.SendStagedPackets()
		} else {
			for _, elemsForPeer := range containers {
				for _, elem := range elemsForPeer.elems {
					device.PutOutboundBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
		}
	}
	return unmatched
}

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	peer.queuedOutboundPackets.Add(int32(len(elems.elems)))
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			peer.queuedOutboundPackets.Add(-int32(len(tooOld.elems)))
			for _, elem := range tooOld.elems {
				peer.device.PutOutboundBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

func (peer *Peer) SendStagedPackets() {
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || sinceIncludingSleep(keypair.created) >= peer.device.keychainExpireTime() {
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		case elemsContainer := <-peer.queue.staged:
			i := 0
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
						elemsContainerOOO.awg = elemsContainer.awg
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				// Already counted at their original staging; StagePackets will count them again.
				peer.queuedOutboundPackets.Add(-int32(len(elemsContainerOOO.elems)))
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			if elemsContainer.awg == nil {
				elemsContainer.awg = peer.device.getAWGConfig()
			}
			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				elemsContainer.filling.Add(1)
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer
			} else {
				peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
				for _, elem := range elemsContainer.elems {
					peer.device.PutOutboundBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
			for _, elem := range elemsContainer.elems {
				peer.device.PutOutboundBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

func (device *Device) randomPaddingAddition(packetSize, mtu int) int {
	addition := device.contentPaddingAddition.Load()

	if addition.IsZero() {
		return -1
	}

	add := int(addition.PickOne())
	if mtu != 0 {
		if packetSize > mtu {
			packetSize %= mtu
		}

		space := mtu - packetSize
		if add > space {
			add = space
		}
	}
	return add
}

func (device *Device) randomTrailer(packetSize int, awg *awgConfig) int {
	if !awg.randomTrailers {
		return -1
	}

	if DefaultUdpWindow < packetSize {
		return 0
	}
	return int(fastrandn(uint32(DefaultUdpWindow - packetSize)))
}

func (peer *Peer) randomTrailer(packetSize int, awg *awgConfig) int {
	if !awg.randomTrailers {
		return -1
	}

	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < packetSize {
		return 0
	}
	return int(fastrandn(uint32(udpWindow - packetSize)))
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elemsContainer := range device.queue.encryption.c {
		awg := elemsContainer.awg
		if awg == nil {
			awg = device.getAWGConfig()
		}
		for _, elem := range elemsContainer.elems {
			udpWindow := elem.padding + MinMessageSize + uint32(len(elem.packet))
			elem.peer.growUDPWindow(udpWindow)

			// fill crypto padding
			cryptStart := MessageEncapsulatingTransportSize
			headerStart := cryptStart + int(elem.padding)
			if headerStart+MessageTransportSize > len(elem.buffer) {
				device.log.Errorf("Routing: AWG transport padding exceeds buffer capacity - packet dropped")
				elem.packet = nil
				continue
			}
			crypt := elem.buffer[cryptStart : cryptStart+int(elem.padding)]
			rand.Read(crypt)

			// populate header fields
			header := elem.buffer[headerStart : headerStart+MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, awg.headers.transport.PickOne())
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			packetSize := len(elem.packet)
			maxPacketSize := len(elem.buffer) - headerStart - MessageTransportSize
			if packetSize > maxPacketSize {
				device.log.Errorf("Routing: transport packet exceeds buffer capacity - packet dropped")
				elem.packet = nil
				continue
			}
			mtu := int(device.tun.mtu.Load())

			paddingSize := device.randomPaddingAddition(packetSize, mtu)
			if paddingSize < 0 {
				paddingSize = elem.peer.randomTrailer(packetSize+MinMessageSize+int(elem.padding), awg)
			}
			if paddingSize < 0 {
				// pad content to multiple of 16
				paddingSize = calculatePaddingSize(packetSize, mtu)
			}
			paddingSize = min(paddingSize, maxPacketSize-packetSize)

			// append trailing zeroes
			oldLen := len(elem.packet)
			elem.packet = slices.Grow(elem.packet, paddingSize)
			elem.packet = elem.packet[:oldLen+paddingSize]
			clear(elem.packet[oldLen:])

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				header,
				nonce[:],
				elem.packet,
				nil,
			)

			cip, err := awg.HeaderProtectionCipher(crypt[:HeaderCipherNonceSize])
			if err != nil {
				device.log.Errorf("Routing: header obfuscation failed - packet dropped")
				elem.packet = nil
				continue
			}
			if cip != nil {
				cip.XORKeyStream(header, header)
			}

			// Re-slice packet to include conn.Bind.Send headroom and AWG prefix padding.
			elem.packet = elem.buffer[:headerStart+len(elem.packet)]
		}
		elemsContainer.filling.Done()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, max(maxBatchSize, conn.IdealBatchSize))

	for elemsContainer := range peer.queue.outbound.c {
		if elemsContainer == nil {
			return
		}
		peer.processOutboundContainer(elemsContainer, bufs[:0])
	}
}

// processOutboundContainer waits for the encryption routine to finish
// filling elemsContainer, then sends the batch (or drops it, if the peer
// has been stopped) and returns the container to the pool.
//
// scratch is a length-0 slice used to assemble the per-packet buffers
// passed to SendBuffers; its backing array is reused across calls.
func (peer *Peer) processOutboundContainer(elemsContainer *QueueOutboundElementsContainer, scratch [][]byte) {
	// Invariants from RoutineSequentialSender; all should be unreachable.
	if len(scratch) != 0 || cap(scratch) == 0 {
		panic(fmt.Sprintf("processOutboundContainer: scratch must be empty with non-zero cap; got len=%d cap=%d",
			len(scratch), cap(scratch)))
	}
	if cap(scratch) < len(elemsContainer.elems) {
		panic(fmt.Sprintf("processOutboundContainer: scratch cap %d < elems %d",
			cap(scratch), len(elemsContainer.elems)))
	}

	device := peer.device
	defer device.PutOutboundElementsContainer(elemsContainer)

	// Wait for RoutineEncryption to finish filling the container. After
	// Wait returns we have happens-before with that goroutine and are the
	// sole owner of the container until Put hands it back to the pool.
	elemsContainer.filling.Wait()

	if !peer.isRunning.Load() {
		// peer has been stopped; return re-usable elems to the shared pool.
		// This is an optimization only. It is possible for the peer to be stopped
		// immediately after this check, in which case, elem will get processed.
		// The timers and SendBuffers code are resilient to a few stragglers.
		// TODO: rework peer shutdown order to ensure
		// that we never accidentally keep timers alive longer than necessary.
		peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
		for _, elem := range elemsContainer.elems {
			device.PutOutboundBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		return
	}

	dataSent := false
	for _, elem := range elemsContainer.elems {
		if len(elem.packet) == 0 {
			continue
		}
		if !elem.isKeepalive {
			dataSent = true
		}
		scratch = append(scratch, elem.packet)
	}

	var err error
	if len(scratch) > 0 {
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()
		err = peer.SendBuffers(scratch)
		if dataSent {
			peer.timersDataSent()
		}
	}
	peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
	for _, elem := range elemsContainer.elems {
		device.PutOutboundBuffer(elem.buffer)
		device.PutOutboundElement(elem)
	}
	if err != nil {
		var errGSO conn.ErrUDPGSODisabled
		if errors.As(err, &errGSO) {
			device.log.Verbosef(err.Error())
			err = errGSO.RetryErr
		}
	}
	if err != nil {
		device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
		return
	}

	peer.keepKeyFreshSending()
}

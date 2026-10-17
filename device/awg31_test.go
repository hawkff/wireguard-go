/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun/tuntest"
)

func newAWGUnitTestDevice(t *testing.T) *Device {
	return newAWGUnitTestDeviceWithBind(t, conn.NewDefaultBind(nil))
}

func newAWGUnitTestDeviceWithBind(t *testing.T, bind conn.Bind) *Device {
	t.Helper()
	tunDevice := tuntest.NewChannelTUN()
	device := NewDevice(context.Background(), tunDevice.TUN(), bind, NewLogger(LogLevelError, ""), 0)
	t.Cleanup(device.Close)
	return device
}

type cookieTestEndpoint struct{}

func (cookieTestEndpoint) ClearSrc()           {}
func (cookieTestEndpoint) SrcToString() string { return "" }
func (cookieTestEndpoint) DstToString() string { return "127.0.0.1:1" }
func (cookieTestEndpoint) DstToBytes() []byte  { return []byte{127, 0, 0, 1, 0, 1} }
func (cookieTestEndpoint) DstIP() netip.Addr   { return netip.MustParseAddr("127.0.0.1") }
func (cookieTestEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type cookieTestBind struct {
	sends    atomic.Int32
	lastSize atomic.Int32
	sendErr  error
}

func (*cookieTestBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 0, nil }
func (*cookieTestBind) Close() error                                    { return nil }
func (*cookieTestBind) SetMark(uint32) error                            { return nil }
func (*cookieTestBind) ParseEndpoint(string) (conn.Endpoint, error)     { return cookieTestEndpoint{}, nil }
func (*cookieTestBind) BatchSize() int                                  { return 1 }
func (*cookieTestBind) SetReservedForEndpoint(netip.AddrPort, [3]byte)  {}
func (bind *cookieTestBind) Send(bufs [][]byte, _ conn.Endpoint, offset int) error {
	bind.sends.Add(int32(len(bufs)))
	for _, buf := range bufs {
		bind.lastSize.Store(int32(len(buf) - offset))
	}
	return bind.sendErr
}

func awgTestPacket(padding uint32, messageSize int, msgType uint32, trailerLen int) []byte {
	packet := make([]byte, int(padding)+messageSize+trailerLen)
	binary.LittleEndian.PutUint32(packet[padding:padding+4], msgType)
	return packet
}

func TestAWG31PacketClassification(t *testing.T) {
	awg := defaultAWGConfig.clone()
	awg.paddings = awgPaddingConfig{init: 12, response: 16, cookie: 20, transport: 24}
	typeHash := make([]byte, 4)

	tests := []struct {
		name        string
		packet      []byte
		expected    uint32
		trailers    bool
		wantSize    int
		wantType    uint32
		wantPadding uint32
	}{
		{
			name:        "fixed initiation",
			packet:      awgTestPacket(awg.paddings.init, MessageInitiationSize, MessageInitiationType, 0),
			expected:    MessageUnknownType,
			wantSize:    MessageInitiationSize,
			wantType:    MessageInitiationType,
			wantPadding: awg.paddings.init,
		},
		{
			name:     "oversized initiation rejected when disabled",
			packet:   awgTestPacket(awg.paddings.init, MessageInitiationSize, MessageInitiationType, 31),
			expected: MessageUnknownType,
		},
		{
			name:        "oversized initiation accepted when enabled",
			packet:      awgTestPacket(awg.paddings.init, MessageInitiationSize, MessageInitiationType, 31),
			expected:    MessageUnknownType,
			trailers:    true,
			wantSize:    MessageInitiationSize,
			wantType:    MessageInitiationType,
			wantPadding: awg.paddings.init,
		},
		{
			name:        "oversized response accepted when enabled",
			packet:      awgTestPacket(awg.paddings.response, MessageResponseSize, MessageResponseType, 17),
			expected:    MessageUnknownType,
			trailers:    true,
			wantSize:    MessageResponseSize,
			wantType:    MessageResponseType,
			wantPadding: awg.paddings.response,
		},
		{
			name:        "oversized cookie accepted when enabled",
			packet:      awgTestPacket(awg.paddings.cookie, MessageCookieReplySize, MessageCookieReplyType, 9),
			expected:    MessageUnknownType,
			trailers:    true,
			wantSize:    MessageCookieReplySize,
			wantType:    MessageCookieReplyType,
			wantPadding: awg.paddings.cookie,
		},
		{
			name:        "variable transport remains accepted when disabled",
			packet:      awgTestPacket(awg.paddings.transport, MessageTransportSize, MessageTransportType, 256),
			expected:    MessageUnknownType,
			wantSize:    MessageTransportSize,
			wantType:    MessageTransportType,
			wantPadding: awg.paddings.transport,
		},
		{
			name:     "expected type remains enforced",
			packet:   awgTestPacket(awg.paddings.init, MessageInitiationSize, MessageInitiationType, 0),
			expected: MessageResponseType,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := awg.clone()
			cfg.randomTrailers = test.trailers
			gotSize, gotType, gotPadding := determinePacketTypeAndPadding(test.packet, test.expected, typeHash, cfg)
			if gotSize != test.wantSize || gotType != test.wantType || gotPadding != test.wantPadding {
				t.Fatalf("classification = (%d, %d, %d), want (%d, %d, %d)", gotSize, gotType, gotPadding, test.wantSize, test.wantType, test.wantPadding)
			}
		})
	}

	// Keep the pre-3.1 exported API source-compatible.
	device := new(Device)
	device.awg.Store(awg)
	packet := awgTestPacket(awg.paddings.init, MessageInitiationSize, MessageInitiationType, 0)
	msgType, padding := device.DeterminePacketTypeAndPadding(packet, MessageInitiationType, typeHash)
	if msgType != MessageInitiationType || padding != awg.paddings.init {
		t.Fatalf("legacy classifier = (%d, %d)", msgType, padding)
	}
}

func TestAWG31UAPIIsTransactional(t *testing.T) {
	device := newAWGUnitTestDevice(t)
	if err := device.IpcSet(uapiCfg(
		"random_trailers", "true",
		"disable_cookies", "true",
	)); err != nil {
		t.Fatal(err)
	}

	awg := device.getAWGConfig()
	if !awg.randomTrailers || !awg.disableCookies {
		t.Fatalf("AWG 3.1 flags were not committed: %+v", awg)
	}
	got, err := device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "random_trailers=1\n") || !strings.Contains(got, "disable_cookies=1\n") {
		t.Fatalf("AWG 3.1 flags missing from UAPI get:\n%s", got)
	}

	// A later validation failure must roll back the flags along with the rest
	// of the immutable AWG configuration snapshot.
	err = device.IpcSet(uapiCfg(
		"random_trailers", "false",
		"disable_cookies", "false",
		"h1", "5",
		"h2", "5",
	))
	if err == nil {
		t.Fatal("overlapping headers unexpectedly accepted")
	}
	awg = device.getAWGConfig()
	if !awg.randomTrailers || !awg.disableCookies {
		t.Fatalf("failed UAPI update partially changed AWG 3.1 flags: %+v", awg)
	}
}

func TestAWGPaddingsRejectOversizedPackets(t *testing.T) {
	device := newAWGUnitTestDevice(t)
	tests := []struct {
		key string
		max int
	}{
		{"s1", MaxMessageSize - MessageInitiationSize},
		{"s2", MaxMessageSize - MessageResponseSize},
		{"s3", MaxMessageSize - MessageCookieReplySize},
		{"s4", MaxMessageSize - MessageEncapsulatingTransportSize - MessageTransportSize},
	}
	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			err := device.IpcSet(uapiCfg(test.key, fmt.Sprint(test.max+1)))
			if err == nil {
				t.Fatalf("%s accepted padding %d above maximum %d", test.key, test.max+1, test.max)
			}
		})
	}
}

func TestAWG31CookieRandomTrailerDoesNotPanic(t *testing.T) {
	bind := new(cookieTestBind)
	device := newAWGUnitTestDeviceWithBind(t, bind)
	var privateKey NoisePrivateKey
	privateKey[0] = 1
	if err := device.IpcSet(uapiCfg(
		"private_key", hex.EncodeToString(privateKey[:]),
		"s3", "400",
		"random_trailers", "true",
	)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, MessageInitiationSize)
	binary.LittleEndian.PutUint32(packet[4:8], 1)
	if err := device.SendHandshakeCookie(&QueueHandshakeElement{packet: packet, endpoint: cookieTestEndpoint{}}); err != nil {
		t.Fatal(err)
	}
	if got := bind.sends.Load(); got != 1 {
		t.Fatalf("cookie sends = %d, want 1", got)
	}
	fixedSize := int32(400 + MessageCookieReplySize)
	if got := bind.lastSize.Load(); got < fixedSize || got >= DefaultUdpWindow {
		t.Fatalf("cookie packet size = %d, want [%d, %d)", got, fixedSize, DefaultUdpWindow)
	}
	sendErr := fmt.Errorf("test cookie send failure")
	bind.sendErr = sendErr
	if err := device.SendHandshakeCookie(&QueueHandshakeElement{packet: packet, endpoint: cookieTestEndpoint{}}); !errors.Is(err, sendErr) {
		t.Fatalf("cookie send error = %v, want %v", err, sendErr)
	}

	if err := device.IpcSet(uapiCfg("disable_cookies", "true")); err != nil {
		t.Fatal(err)
	}
	bind.sendErr = nil
	if err := device.SendHandshakeCookie(&QueueHandshakeElement{packet: packet, endpoint: cookieTestEndpoint{}}); err != nil {
		t.Fatal(err)
	}
	if got := bind.sends.Load(); got != 3 {
		t.Fatalf("manual cookie sends were blocked when disable_cookies was enabled: %d", got)
	}
}

func TestAWG31UnknownProtectedPacketDoesNotPanic(t *testing.T) {
	device := newAWGUnitTestDevice(t)
	deadline := time.Now().Add(2 * time.Second)
	for !device.isUp() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !device.isUp() {
		t.Fatal("device did not process the initial TUN up event")
	}
	if err := device.Down(); err != nil {
		t.Fatal(err)
	}

	headerKey := bytes.Repeat([]byte{0x42}, HeaderCipherKeySize)
	if err := device.IpcSet(uapiCfg(
		"s1", "24",
		"s2", "24",
		"s3", "24",
		"s4", "24",
		"header_protection_key", hex.EncodeToString(headerKey),
		"random_trailers", "true",
	)); err != nil {
		t.Fatal(err)
	}

	packet := make([]byte, 200)
	awg := device.getAWGConfig()
	cipher, err := awg.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
	if err != nil {
		t.Fatal(err)
	}
	var typeHash [4]byte
	cipher.XORKeyStream(typeHash[:], typeHash[:])
	var unknownHeader [4]byte
	binary.LittleEndian.PutUint32(unknownHeader[:], 999)
	applyHash(packet[awg.paddings.transport:awg.paddings.transport+4], unknownHeader[:], typeHash[:])

	calls := 0
	recv := conn.ReceiveFunc(func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		calls++
		if calls == 1 {
			copy(packets[0], packet)
			sizes[0] = len(packet)
			return 1, nil
		}
		return 0, net.ErrClosed
	})
	device.queue.decryption.wg.Add(1)
	device.queue.handshake.wg.Add(1)
	device.net.stopping.Add(1)
	device.RoutineReceiveIncoming(1, recv)
	if calls != 2 {
		t.Fatalf("receive calls = %d, want 2", calls)
	}
}

func TestAWG31DevicePing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false,
		"s1", "24",
		"s2", "28",
		"s3", "32",
		"s4", "36",
		"h1", "123456-123500",
		"h2", "67543-67550",
		"h3", "123123-123200",
		"h4", "32345-32350",
		"header_protection_key", "4242424242424242424242424242424242424242424242424242424242424242",
		"random_trailers", "true",
		"disable_cookies", "true",
	)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	for key, peer := range pair[0].dev.peers.keyMap {
		peer.growUDPWindow(900)
		peer.growUDPWindow(700)
		if got := peer.udpWindow.Load(); got != 900 {
			t.Fatalf("UDP window shrank to %d", got)
		}
		if err := pair[0].dev.IpcSet(uapiCfg(
			"public_key", hex.EncodeToString(key[:]),
			"endpoint", "127.0.0.1:1",
		)); err != nil {
			t.Fatal(err)
		}
		if got := peer.udpWindow.Load(); got != DefaultUdpWindow {
			t.Fatalf("UDP window after endpoint update = %d, want %d", got, DefaultUdpWindow)
		}
	}
}

func TestAWG31UDPWindowTracksWireSize(t *testing.T) {
	goroutineLeakCheck(t)
	const transportPadding = 600
	pair := genTestPair(t, false, "s4", fmt.Sprint(transportPadding))
	pair.Send(t, Ping, nil)

	var receiver *Peer
	for _, candidate := range pair[0].dev.peers.keyMap {
		receiver = candidate
	}
	if receiver == nil {
		t.Fatal("receiver peer not found")
	}
	payloadSize := len(tuntest.Ping(pair[0].ip, pair[1].ip))
	want := uint32(transportPadding + MinMessageSize + payloadSize)
	if got := receiver.udpWindow.Load(); got != want {
		t.Fatalf("learned UDP window = %d, want full wire size %d", got, want)
	}
}

func TestAWGPaddedKeepaliveIsNotData(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false,
		"s4", "25",
		"content_padding_addition", "5-31",
	)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	var sender, receiver *Peer
	for _, candidate := range pair[1].dev.peers.keyMap {
		sender = candidate
	}
	for _, candidate := range pair[0].dev.peers.keyMap {
		receiver = candidate
	}
	if sender == nil || receiver == nil {
		t.Fatal("sender or receiver peer not found")
	}

	// A padded keepalive has a non-empty decrypted payload of zero bytes. It
	// must count as authenticated traffic, but not as data that schedules the
	// receiver's send-keepalive timer.
	receiver.timers.sendKeepalive.DelSync()
	receiver.timers.needAnotherKeepalive.Store(false)
	startRX := receiver.rxBytes.Load()
	sender.SendKeepalive()
	deadline := time.Now().Add(2 * time.Second)
	for receiver.rxBytes.Load() == startRX && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if receiver.rxBytes.Load() == startRX {
		t.Fatal("padded keepalive was not received")
	}
	graceDeadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(graceDeadline) {
		if receiver.timers.sendKeepalive.IsPending() || receiver.timers.needAnotherKeepalive.Load() {
			t.Fatal("padded keepalive scheduled a response as if it were data")
		}
		time.Sleep(time.Millisecond)
	}
}

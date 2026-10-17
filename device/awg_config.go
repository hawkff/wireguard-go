package device

import "errors"

type awgConfig struct {
	junk                awgJunkConfig
	headers             awgHeaderConfig
	paddings            awgPaddingConfig
	ipackets            [5]*obfChain
	headerProtectionKey HeaderCipherKey
	randomTrailers      bool
	disableCookies      bool
}

type awgJunkConfig struct {
	min   uint32
	max   uint32
	count uint32
}

type awgHeaderConfig struct {
	init      UintRange
	cookie    UintRange
	response  UintRange
	transport UintRange
}

type awgPaddingConfig struct {
	init      uint32
	response  uint32
	cookie    uint32
	transport uint32
}

var defaultAWGConfig = &awgConfig{
	headers: awgHeaderConfig{
		init:      newUintRange(MessageInitiationType, MessageInitiationType),
		response:  newUintRange(MessageResponseType, MessageResponseType),
		cookie:    newUintRange(MessageCookieReplyType, MessageCookieReplyType),
		transport: newUintRange(MessageTransportType, MessageTransportType),
	},
}

func newUintRange(lo, hi uint32) UintRange {
	var r UintRange
	r.FromUint32(lo, hi)
	return r
}

func (device *Device) getAWGConfig() *awgConfig {
	cfg := device.awg.Load()
	if cfg != nil {
		return cfg
	}
	return defaultAWGConfig
}

func (cfg *awgConfig) clone() *awgConfig {
	next := *cfg
	return &next
}

func validateAWGHeaders(headers awgHeaderConfig) error {
	all := []UintRange{headers.init, headers.response, headers.cookie, headers.transport}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[i].Overlap(all[j]) {
				return errors.New("headers must not overlap")
			}
		}
	}
	return nil
}

func validateAWGPaddings(paddings awgPaddingConfig) error {
	limits := []struct {
		name  string
		value uint32
		max   int
	}{
		{"S1", paddings.init, MaxMessageSize - MessageInitiationSize},
		{"S2", paddings.response, MaxMessageSize - MessageResponseSize},
		{"S3", paddings.cookie, MaxMessageSize - MessageCookieReplySize},
		{"S4", paddings.transport, MaxMessageSize - MessageEncapsulatingTransportSize - MessageTransportSize},
	}
	for _, limit := range limits {
		if uint64(limit.value) > uint64(limit.max) {
			return errors.New(limit.name + " exceeds the packet buffer capacity")
		}
	}
	return nil
}

package interceptor

import (
	"encoding/binary"
	"errors"
	"middleware/pkg/pipeline"
)

func ExtractTLSSNI(payload []byte) (string, error) {
	if len(payload) < 5 {
		return "", errors.New("payload too short for TLS")
	}

	if payload[0] != 0x16 {
		return "", errors.New("unsupported protocol version packet")
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return "", errors.New("incomplete TLS record")
	}

	data := payload[5 : 5+recordLen]
	if len(data) < 4 {
		return "", errors.New("invalid handshake payload")
	}

	if data[0] != 0x01 {
		return "", errors.New("not a TLS Client Handshake")
	}

	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		return "", errors.New("incomplete Client payload")
	}

	pos := 38
	if len(data) < pos {
		return "", errors.New("truncated Client data")
	}

	if len(data) < pos+1 {
		return "", errors.New("truncated session ID length")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if len(data) < pos+2 {
		return "", errors.New("truncated cipher suites length")
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherLen

	if len(data) < pos+1 {
		return "", errors.New("truncated compression methods length")
	}
	compLen := int(data[pos])
	pos += 1 + compLen

	if len(data) < pos+2 {
		return "", errors.New("no extensions present")
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if len(data) < pos+extLen {
		return "", errors.New("truncated extensions payload")
	}

	extBytes := data[pos : pos+extLen]

	extPos := 0
	for extPos+4 <= len(extBytes) {
		extType := binary.BigEndian.Uint16(extBytes[extPos : extPos+2])
		extDataLen := int(binary.BigEndian.Uint16(extBytes[extPos+2 : extPos+4]))
		extPos += 4

		if extPos+extDataLen > len(extBytes) {
			break
		}

		if extType == 0x0000 {
			sniData := extBytes[extPos : extPos+extDataLen]
			if len(sniData) < 5 {
				return "", errors.New("invalid SNI extension length")
			}

			if sniData[2] != 0x00 {
				return "", errors.New("unsupported SNI name type")
			}

			nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
			if nameLen <= 0 || len(sniData) < 5+nameLen {
				return "", errors.New("invalid SNI name length")
			}

			name := pipeline.SanitizeDomain(string(sniData[5 : 5+nameLen]))
			if name == "" {
				return "", errors.New("invalid SNI hostname")
			}
			return name, nil
		}

		extPos += extDataLen
	}
	return "", errors.New("SNI extension not found")
}

func IsTLSClientHello(payload []byte) bool {
	return len(payload) >= 6 && payload[0] == 0x16 && payload[5] == 0x01
}

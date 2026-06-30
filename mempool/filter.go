package mempool

import (
	"errors"
	"fmt"

	"github.com/cometbft/cometbft/config"
)

// Protobuf wire types we need to recognise while scanning a mempool message.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

var (
	errVarintOverflow  = errors.New("malformed mempool message: varint overflow")
	errTruncatedVarint = errors.New("malformed mempool message: truncated varint")
	errOutOfBounds     = errors.New("malformed mempool message: length out of bounds")
)

// gossipBatchByteBudget returns the maximum number of raw transaction bytes a
// well-behaved peer can pack into a single mempool gossip message.
//
// The broadcaster (see AppReactor.OnStart and chunkTxs) chunks batches by
// MaxBatchBytes when set, otherwise by MaxTxBytes. A single transaction can
// independently be as large as MaxTxBytes regardless of MaxBatchBytes (the
// classic reactor gossips one tx per message), so the budget is the larger of
// the two. A non-positive result means "unbounded" and disables the total-size
// check, mirroring how MaxTxBytes <= 0 disables the per-tx limit elsewhere.
func gossipBatchByteBudget(cfg *config.MempoolConfig) int {
	return max(cfg.MaxTxBytes, cfg.MaxBatchBytes)
}

// filterMempoolMsgBytes walks the protobuf wire bytes of a
// tendermint.mempool.Message just enough to validate the transaction batch it
// carries, WITHOUT performing the full (allocating) unmarshal. It allocates
// nothing: it counts the Txs.txs entries and sums their declared sizes while
// rejecting anything a well-behaved peer would never send.
//
// This recouples the number of decoded elements to the wire byte cost. Without
// it, a peer can pack a very large number of zero/one-byte `txs` entries into a
// single message that fits under RecvMessageCapacity, then the receive path
// allocates one slice header per entry (in the proto [][]byte and again in
// txsFromEnvelope's make([]types.Tx, N)), driving heap use far above the wire
// size. Rejecting empty entries forces every counted entry to consume real
// bytes, and maxBatchBytes then bounds the total work to O(wire size).
//
// maxTxBytes is the per-transaction limit (0 = unlimited); maxBatchBytes is the
// total raw-tx-bytes budget for the message (0 = unlimited).
func filterMempoolMsgBytes(msgBytes []byte, maxTxBytes, maxBatchBytes int) error {
	count := 0
	totalBytes := 0

	// Outer message: tendermint.mempool.Message { oneof sum { Txs txs = 1; } }.
	for i := 0; i < len(msgBytes); {
		fieldNum, wireType, n, err := consumeTag(msgBytes[i:])
		if err != nil {
			return err
		}
		i += n

		if fieldNum == 1 && wireType == wireBytes {
			msgLen, n, err := consumeVarint(msgBytes[i:])
			if err != nil {
				return err
			}
			i += n
			end := i + int(msgLen)
			if end < i || end > len(msgBytes) {
				return errOutOfBounds
			}
			// A oneof may legally appear more than once on the wire; gogoproto
			// merges repeated Txs submessages, so accumulate across all of them.
			if err := scanTxsSubmessage(msgBytes[i:end], maxTxBytes, maxBatchBytes, &count, &totalBytes); err != nil {
				return err
			}
			i = end
		} else {
			skip, err := skipField(msgBytes[i:], wireType)
			if err != nil {
				return err
			}
			i += skip
		}
	}

	if count == 0 {
		return errors.New("mempool message contains no transactions")
	}
	return nil
}

// scanTxsSubmessage walks a tendermint.mempool.Txs { repeated bytes txs = 1; }
// submessage, validating and counting each entry without copying its bytes.
func scanTxsSubmessage(b []byte, maxTxBytes, maxBatchBytes int, count, totalBytes *int) error {
	for i := 0; i < len(b); {
		fieldNum, wireType, n, err := consumeTag(b[i:])
		if err != nil {
			return err
		}
		i += n

		if fieldNum == 1 && wireType == wireBytes {
			txLen, n, err := consumeVarint(b[i:])
			if err != nil {
				return err
			}
			i += n
			end := i + int(txLen)
			if end < i || end > len(b) {
				return errOutOfBounds
			}

			if txLen == 0 {
				return errors.New("mempool batch contains an empty transaction")
			}
			if maxTxBytes > 0 && int(txLen) > maxTxBytes {
				return fmt.Errorf("transaction size %d exceeds max_tx_bytes %d", txLen, maxTxBytes)
			}
			*count++
			*totalBytes += int(txLen)
			if maxBatchBytes > 0 && *totalBytes > maxBatchBytes {
				return fmt.Errorf("mempool batch exceeds %d byte budget", maxBatchBytes)
			}

			i = end
		} else {
			skip, err := skipField(b[i:], wireType)
			if err != nil {
				return err
			}
			i += skip
		}
	}
	return nil
}

// consumeTag reads a protobuf field tag, returning the field number, wire type,
// and the number of bytes consumed.
func consumeTag(b []byte) (fieldNum, wireType, n int, err error) {
	v, n, err := consumeVarint(b)
	if err != nil {
		return 0, 0, 0, err
	}
	fieldNum = int(v >> 3)
	wireType = int(v & 0x7)
	if fieldNum <= 0 {
		return 0, 0, 0, fmt.Errorf("malformed mempool message: illegal field number %d", fieldNum)
	}
	return fieldNum, wireType, n, nil
}

// consumeVarint reads a base-128 varint and returns its value and the number of
// bytes consumed.
func consumeVarint(b []byte) (uint64, int, error) {
	var v uint64
	for shift := uint(0); ; shift += 7 {
		if shift >= 64 {
			return 0, 0, errVarintOverflow
		}
		idx := int(shift / 7)
		if idx >= len(b) {
			return 0, 0, errTruncatedVarint
		}
		c := b[idx]
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, idx + 1, nil
		}
	}
}

// skipField advances past a field whose value we don't care about, returning
// the number of bytes consumed for the given wire type.
func skipField(b []byte, wireType int) (int, error) {
	switch wireType {
	case wireVarint:
		_, n, err := consumeVarint(b)
		return n, err
	case wireFixed64:
		if len(b) < 8 {
			return 0, errOutOfBounds
		}
		return 8, nil
	case wireBytes:
		l, n, err := consumeVarint(b)
		if err != nil {
			return 0, err
		}
		end := n + int(l)
		if end < n || end > len(b) {
			return 0, errOutOfBounds
		}
		return end, nil
	case wireFixed32:
		if len(b) < 4 {
			return 0, errOutOfBounds
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("malformed mempool message: unsupported wire type %d", wireType)
	}
}

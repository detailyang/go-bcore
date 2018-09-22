package bcore

// One thing all signature hash types sign is the transaction’s locktime. (Called nLockTime in the Bitcoin Core source code.) The locktime indicates the earliest time a transaction can be added to the block chain.

// Locktime allows signers to create time-locked transactions which will only become valid in the future, giving the signers a chance to change their minds.

// If any of the signers change their mind, they can create a new non-locktime transaction. The new transaction will use, as one of its inputs, one of the same outputs which was used as an input to the locktime transaction. This makes the locktime transaction invalid if the new transaction is added to the block chain before the time lock expires.

// Care must be taken near the expiry time of a time lock. The peer-to-peer network allows block time to be up to two hours ahead of real time, so a locktime transaction can be added to the block chain up to two hours before its time lock officially expires. Also, blocks are not created at guaranteed intervals, so any attempt to cancel a valuable transaction should be made a few hours before the time lock expires.

// Previous versions of Bitcoin Core provided a feature which prevented transaction signers from using the method described above to cancel a time-locked transaction, but a necessary part of this feature was disabled to prevent denial of service attacks. A legacy of this system are four-byte sequence numbers in every input. Sequence numbers were meant to allow multiple signers to agree to update a transaction; when they finished updating the transaction, they could agree to set every input’s sequence number to the four-byte unsigned maximum (0xffffffff), allowing the transaction to be added to a block even if its time lock had not expired.

// Even today, setting all sequence numbers to 0xffffffff (the default in Bitcoin Core) can still disable the time lock, so if you want to use locktime, at least one input must have a sequence number below the maximum. Since sequence numbers are not used by the network for any other purpose, setting any sequence number to zero is sufficient to enable locktime.

// Locktime itself is an unsigned 4-byte integer which can be parsed two ways:

// If less than 500 million, locktime is parsed as a block height. The transaction can be added to any block which has this height or higher.

// If greater than or equal to 500 million, locktime is parsed using the Unix epoch time format (the number of seconds elapsed since 1970-01-01T00:00 UTC—currently over 1.395 billion). The transaction can be added to any block whose block time is greater than the locktime.

import "errors"

const (
	TransactionCheckerLocktimeThreshold = 500000000
	// TransactionCheckerLocktimeSequenceFinal Setting nSequence to this value for every input in a transaction
	// disables nLockTime.
	TransactionCheckerLocktimeSequenceFinal = 0xffffffff

	// TransactionSequenceLocktimeDisableFlag apply in the context of BIP 68
	// If this flag set, sequence is NOT interpreted as a
	// relative lock-time.
	TransactionSequenceLocktimeDisableFlag = 1 << 31

	// If txinput->Sequence encodes a relative lock-time and this flag
	// is set, the relative lock-time has units of 512 seconds,
	// otherwise it specifies blocks with a granularity of 1.
	TransactionSequenceLockTimeTypeFlag = uint32(1 << 22)
	// If txinput->sequence encodes a relative lock-time, this mask is
	// applied to extract that lock-time from the sequence field.
	TransactionSequenceLocktimeMask = uint32(0x0000ffff)
)

var (
	ErrTransactionCheckerLockTimeThreshold     = errors.New("transaction checker: locktime < threshold")
	ErrTransactionCheckerLockTimeNotArrived    = errors.New("transaction checker: locktime has not arrived")
	ErrTransactionCheckerLocktimeSequenceFinal = errors.New("transaction checker: final sequence")
	ErrTransactionCheckerSequenceLowVersion    = errors.New("transaction checker: transaction version below 2")
	ErrTransactionCheckerSequenceDisabled      = errors.New("transaction checker: sequence disabled")
	ErrTransactionCheckerSequenceThresold      = errors.New("transaction checker: sequence < threshold")
)

type TransactionChecker struct {
	Transaction *Transaction
	InputIndex  int
}

func (ck *TransactionChecker) CheckLockTime(locktime uint32) error {
	// There are two kinds of nLockTime: lock-by-blockheight
	// and lock-by-blocktime, distinguished by whether
	// nLockTime < LOCKTIME_THRESHOLD.
	//
	// We want to compare apples to apples, so fail the script
	// unless the type of nLockTime being tested is the same as
	// the nLockTime in the transaction.

	if !((ck.Transaction.Locktime < TransactionCheckerLocktimeThreshold &&
		locktime < TransactionCheckerLocktimeThreshold) ||
		(ck.Transaction.Locktime >= TransactionCheckerLocktimeThreshold &&
			locktime >= TransactionCheckerLocktimeThreshold)) {
		return ErrTransactionCheckerLockTimeThreshold
	}

	if locktime > ck.Transaction.Locktime {
		return ErrTransactionCheckerLockTimeNotArrived
	}

	if TransactionFinalSequence != ck.Transaction.Inputs[ck.InputIndex].Sequence {
		return ErrTransactionCheckerLocktimeSequenceFinal
	}

	return nil
}

func (ck *TransactionChecker) CheckSequence(sequence uint32) error {
	// Fail if the transaction's version number is not set high
	// enough to trigger BIP 68 rules.
	if ck.Transaction.Version < 2 {
		return ErrTransactionCheckerSequenceLowVersion
	}

	if ck.Transaction.Inputs[ck.InputIndex].Sequence&TransactionSequenceLocktimeDisableFlag ==
		TransactionSequenceLocktimeDisableFlag {
		return ErrTransactionCheckerSequenceDisabled
	}

	locktimeMask := TransactionSequenceLockTimeTypeFlag | TransactionSequenceLocktimeMask
	tsequence := ck.Transaction.Inputs[ck.InputIndex].Sequence & locktimeMask
	sequence = sequence & locktimeMask

	// There are two kinds of nSequence: lock-by-blockheight
	// and lock-by-blocktime, distinguished by whether
	// nSequenceMasked < TransactionSequenceLockTimeTypeFlag.

	// We want to compare apples to apples, so fail the script
	// unless the type of nSequenceMasked being tested is the same as
	// the nSequenceMasked in the transaction.
	if !((tsequence < TransactionSequenceLockTimeTypeFlag && locktimeMask < TransactionSequenceLockTimeTypeFlag) ||
		(tsequence >= TransactionSequenceLockTimeTypeFlag && locktimeMask >= TransactionSequenceLockTimeTypeFlag)) {
		return ErrTransactionCheckerSequenceThresold
	}

	if tsequence < sequence {

	}

	return nil
}

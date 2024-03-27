#!/usr/bin/env python3

from enum import Enum
import struct
import blake3
import base58

config_file_name ="dsc-config.yaml"
msg_encoding = "utf-8"


NEW_HASH_INTERVAL = 6

BLOCKCHAIN_DIFFICULTY = 15
PROOF_HASH_MEMORY_SIZE = 100 * 1024 * 1024
BLOCKCHAIN_VALIDATE_HASH_SIZE = 24

MAX_TRANSACTION_PER_BLOCK = 8191

BLOCK_HEADER_BYTES = 128
TRANSACTION_BYTES = 128

BLOCKCHAIN_REWARD = 1.0

class ProofType(Enum):
	ProofOfWork = 0
	ProofOfMemory = 1

PROOF_STR_2_TYPE = {
	"pow" : ProofType.ProofOfWork,
	"pom" : ProofType.ProofOfMemory
}

class RequestType(Enum):
	WalletSend = 0
	WalletBalance = 1
	WalletBcTransactions = 2
	WalletPoolTransactionState = 3

	WalletBcTransactionDetail = 5
	
	ValidatorBcRegister = 15
	ValidatorPoolRegister = 16
	ValidatorMnRegister = 17

	ValidatorBcNewBlock = 28
	ValidatorMnFoundNonce = 29
	ValidatorPoolGrabTransactions = 30

	PoolBcRegister = 45
	PoolBcTransactionState = 46

	MetronomeBcHash = 50
	BcMetronomeRegister = 51
	


class ResponseType(Enum):
	PoolWalletTransactionState = 100
	WalletBalance =  101
	WalletTransactionSubmitted =  102
	BcWalletTransactions = 103
	BcTargetHash = 110
	BcPoolTransState = 111
	PoolValidatorGrabTransactions = 112


	MetronomeValidatorWinner = 150
	MetronomeBcBeat = 151
	MetronomeDifficulty = 152
	MetronomeValidatorApproved = 153
	MetronomeValidatorNotApproved = 154

	BcPoolTransactionsResult = 150


class TransactionState(Enum):
	submited = 0
	unconfirmed = 1
	confirmed = 2
	failed = 3
	unknown = 4


TRANS_STATE_VAL_TO_STR = {
	TransactionState.submited.value : "submited",
	TransactionState.unconfirmed.value : "unconfirmed",
	TransactionState.confirmed.value : "confirmed",
	TransactionState.failed.value : "failed",
	TransactionState.unknown.value : "unknown"
}

def GenerateRandomBytes():
	import random
	return bytes(random.randint(0, 255) for _ in range(8))

def LoadConfig():
	import os
	import yaml
	config = None
	cur_dir = os.path.dirname(os.path.abspath(__file__))
	global config_file_name
	with open(os.path.join(cur_dir, config_file_name), 'r') as f:
		config = yaml.safe_load(f)
	return config

async def ExactRead(reader):
	result = None
	try:
		prefix = await reader.readexactly(4)
		msg_len = struct.unpack('!I', prefix)[0]
		result = await reader.readexactly(msg_len)
	except:
		pass
	return result

def SyncExactWrite(writer, msg):
	msg_len = len(msg)
	try:
		writer.write(struct.pack('!I', msg_len))
		writer.write(msg)
	except:
		pass
	
async def ExactWrite(writer, msg):
	assert msg is not None, "ExactWrite: msg is None"
	msg_len = len(msg)
	try:
		writer.write(struct.pack('!I', msg_len))
		writer.write(msg)
		await writer.drain()
	except:
		pass

def GetFirstNBits(bytes_str, num):
	return ''.join(format(byte, '08b') for byte in bytes_str[0: int(num / 8 + 1)])[0: num]

def LogMsg(msg):
	import datetime
	current_time = datetime.datetime.now()
	print("{0}{1}{2} {3} {4}".format(current_time.year, current_time.month, 
						  current_time.day, str(current_time.time())[:-3], msg))

def FingerprintBytesToStr(fingerprint_bytes):
	import uuid
	return str(uuid.UUID(bytes=fingerprint_bytes))

def TimeStrFromTimestamp(timestamp):
	import datetime
	return datetime.datetime.fromtimestamp(timestamp).strftime('%Y%m%d %H:%M:%S')

def Base58Str(bytes_str):
	return base58.b58encode_check(bytes_str).decode('utf-8')

def Base58ToBytes(base58_str):
	return base58.b58decode_check(base58_str)

def ValidatorFormBlake3Param(fingerprint_bytes, public_key_bytes, nonce):
	return fingerprint_bytes + public_key_bytes + nonce.to_bytes(4, 'big')

def ParseTransaction(trans_bytes):
	"""
	Transaction (128B)
		Sender Public Address (32B)
		Recipient Public Address (32B)
		Value (unsigned double, 8B)
		Timestamp (signed integer 8B)
		Transaction ID (16B)
		Signature (32B)
	"""
	result = {}
	result['sender'] = trans_bytes[0:32]
	result['recipient'] = trans_bytes[32:64]
	result['value'] = struct.unpack('!d', trans_bytes[64:72])[0]
	result['timestamp'] = struct.unpack('!Q', trans_bytes[72:80])[0]
	result['id'] = trans_bytes[80:96]
	result['signature'] = trans_bytes[96:128]
	return result

def TransactionDictToBytes(trans):
	"""
	Transaction (128B)
		Sender Public Address (32B)
		Recipient Public Address (32B)
		Value (unsigned double, 8B)
		Timestamp (signed integer 8B)
		Transaction ID (16B)
		Signature (32B)
	"""
	trans_msg = trans['sender']
	trans_msg += trans['recipient']
	trans_msg += struct.pack('!d', trans['value'])
	trans_msg += struct.pack('!Q', trans['timestamp'])
	trans_msg += trans['id']
	trans_msg += trans['signature']
	return trans_msg

# skip Array of Transactions, return block bytes until Reserved.
def BlockDictToBytes(block, trans_size):
	"""
	Block (128B header + 128B*#trans) – multiple transactions will be stored in a block on the blockchain
		Block Size (unsigned integer 4B)
		Block Header (56B)
			Version (unsigned short integer 2B)
			Previous Block Hash (32B)
			BlockID (unsigned integer 4B)
			Timestamp (signed integer 8B)
			Difficulty Target (unsigned short integer 2B)
			Nonce (unsigned integer 8B)
		Transaction Counter (unsigned integer 4B)
		Reserved (64B)
		Array of Transactions (variable)
	"""
	# 4B
	message = struct.pack('!I', 128 + 128 * trans_size)	
	# 2B	
	message += struct.pack('!H', block['version'])
	# 32B
	message += block['previous_block_hash']
	# 4B
	message += struct.pack('!I', block['block_id'])
	# 8B
	message += struct.pack('!Q', block['timestamp'])
	# 2B
	message += struct.pack('!H', block['difficulty_target'])
	# 8B
	message += struct.pack('!Q', block['nonce'])
	# 4B
	message += struct.pack('!I', trans_size)
	reserved = bytes(64)
	message += reserved
	return message

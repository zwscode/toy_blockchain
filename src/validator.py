#!/usr/bin/env python3
from dsc_defines import LogMsg
import dsc_defines
import blake3
import asyncio
import struct
import time
import threading
import uuid

g_Validator = None

def GetValidator():
	global g_Validator
	if g_Validator is None:
		g_Validator = CValidator()
	return g_Validator


class CValidator(object):

	def __init__(self):
		self.m_difficulty = dsc_defines.BLOCKCHAIN_DIFFICULTY
		self.m_target_hash = None
		# length of the blocks in blockchain
		self.m_block_len = 0
		self.m_stop_working_thread = False

		self.m_config = dsc_defines.LoadConfig()
		self.m_work_lock = threading.Lock()
		self.m_pow_hash_count = 0

		self.m_hash_memory = []
		self.m_fingerprint = uuid.uuid4()
		self.m_bc_writer = None
		self.m_mn_writer = None
		self.m_pool_writer = None
		# used for pom
		self.m_hash_memory_ready = False
		self.LoadConfig()
		LogMsg("Fingerprint: {}".format(str(self.m_fingerprint)))

	def LoadConfig(self):
		proof_str = self.m_config["Validator"]["proof_type"]
		self.m_proof_type = dsc_defines.PROOF_STR_2_TYPE.get(proof_str, dsc_defines.ProofType.ProofOfWork)
		self.m_public_key_bytes = dsc_defines.Base58ToBytes(self.m_config["Wallet"]["public_key"])
		if (self.m_proof_type == dsc_defines.ProofType.ProofOfMemory):
			self.GenerateHashMemory()

	def GenerateHashMemory(self):
		import os
		from functools import cmp_to_key
		num = dsc_defines.PROOF_HASH_MEMORY_SIZE // (dsc_defines.BLOCKCHAIN_VALIDATE_HASH_SIZE + 8)
		hash_mem = self.m_hash_memory
		LogMsg("[POM] start generating hashes")
		for i in range(num):
			hash = blake3.blake3(dsc_defines.ValidatorFormBlake3Param(self.m_fingerprint.bytes, self.m_public_key_bytes, i)).digest(length=dsc_defines.BLOCKCHAIN_VALIDATE_HASH_SIZE)
			hash_mem.append((i, hash))
		LogMsg("[POM] finished generating hashes")
		def my_compare(item1, item2):
			item1_bytes = item1[1]
			item2_bytes = item2[1]
			if item1_bytes < item2_bytes:
				return -1
			elif item1_bytes > item2_bytes:
				return 1
			else:
				return 0	
		hash_mem.sort(key=cmp_to_key(my_compare))
		self.m_hash_memory_ready = True
		LogMsg("[POM] finished sorting hashes")

	def OnReceiveTargetHash(self, hash, block_len):
		if (hash != self.m_target_hash):
			self.m_pow_hash_count = 0

		self.m_target_hash = hash
		self.m_block_len = block_len
		self.m_target_hash_time = time.time()
		LogMsg("validator received target hash {}".format(dsc_defines.Base58Str(self.m_target_hash)))
		self.m_nonce = 0
		with self.m_work_lock:
			self.m_stop_working_thread = True

		if self.m_proof_type == dsc_defines.ProofType.ProofOfWork:
			threading.Timer(0, self.PowMining).start()
		elif self.m_proof_type == dsc_defines.ProofType.ProofOfMemory:
			self.PomMining()
	
	def BinarySearchHash(self, target_bits):
		low = 0
		arr = self.m_hash_memory
		high = len(arr) - 1

		while low <= high:
			mid = (low + high) // 2
			mid_val = arr[mid]
			mid_val_bits = dsc_defines.GetFirstNBits(mid_val[1], self.m_difficulty)
			if mid_val_bits == target_bits:
				return mid
			elif mid_val_bits < target_bits:
				low = mid + 1
			else:
				high = mid - 1

		return -1  # Target value not found

	def PomMining(self):
		# compare target_hash with hashes in self.m_hash_memory try to find nonce
		# if found, send nonce to blockchain
		if not self.m_hash_memory:
			print("PomMining, hash memory is empty")
			return
		if not self.m_target_hash:
			print("PomMining, target hash is empty")
			return
		if not self.m_hash_memory_ready:
			print("PomMining, hash memory is not ready")
			return
		with self.m_work_lock:
			self.m_nonce = None
		validate_bits = dsc_defines.GetFirstNBits(self.m_target_hash, self.m_difficulty)
		# do binary search in hash_memory to find the nonce
		search_idx = self.BinarySearchHash(validate_bits)
		# print("BinarySearchHash result", search_idx)
		if search_idx == -1:
			LogMsg("[POM] block {}, nonce -1, diff {}".format(self.m_block_len, self.m_difficulty))
			return
		self.m_nonce = self.m_hash_memory[search_idx][0]
		LogMsg("[POM] block {}, nonce {}, diff {}".format(self.m_block_len, self.m_nonce, self.m_difficulty))
		self.SendNonceToMetronome()

	def PowMining(self):
		with self.m_work_lock:
			self.m_stop_working_thread = False
			self.m_nonce = 0

		difficulty = self.m_difficulty
		# a byte have 8 bits, so divide by 8
		compare_bytes = difficulty // 8
		validate_bits = dsc_defines.GetFirstNBits(self.m_target_hash, difficulty)
		start_time = self.m_target_hash_time
		block_len = self.m_block_len

		if not self.m_mn_writer:
			print("metronome not found, abort mining")
			return
		count = 0
		found_nounce = False
		while time.time() - start_time < dsc_defines.NEW_HASH_INTERVAL:
			blake_param_bytes = dsc_defines.ValidatorFormBlake3Param(self.m_fingerprint.bytes, self.m_public_key_bytes, self.m_nonce)
			generated_hash = blake3.blake3(blake_param_bytes).digest(length=dsc_defines.BLOCKCHAIN_VALIDATE_HASH_SIZE)
			if (generated_hash[0:compare_bytes] == self.m_target_hash[0:compare_bytes]):
				if dsc_defines.GetFirstNBits(generated_hash, difficulty) == validate_bits:
					found_nounce = True
					break
			count += 1
			self.m_nonce += 1
			if self.m_stop_working_thread:
				break
		self.m_pow_hash_count += count
		hash_rate = int(count / (time.time() - start_time))
		if found_nounce:
			LogMsg(f"[POW] block {block_len}, NONCE {self.m_nonce}, ({hash_rate}Hash/s)")
			self.SendNonceToMetronome()
		else:
			LogMsg(f"[POW] block {block_len}, NONCE -1, ({hash_rate}Hash/s)")
			

	def SendNonceToMetronome(self):
		message = struct.pack('!I', dsc_defines.RequestType.ValidatorMnFoundNonce.value)
		# 16B
		message += self.m_fingerprint.bytes
		# 32B
		message += self.m_public_key_bytes
		# 8B
		message += struct.pack('!Q', self.m_nonce)
		dsc_defines.SyncExactWrite(self.m_mn_writer, message)

	async def ConnectToBlockchain(self):
		bc_config = self.m_config["Blockchain"]
		bc_ip = bc_config["ip"]
		bc_port = int(bc_config["port"])
		reader, writer = None, None
		while True:
			try:
				reader, writer = await asyncio.open_connection(bc_ip, bc_port)
				break
			except:
				await asyncio.sleep(1)
				continue
		print("connected to blockchain")
		self.m_bc_writer = writer
		register_msg = struct.pack('!I', dsc_defines.RequestType.ValidatorBcRegister.value)
		register_msg += self.m_fingerprint.bytes
		await dsc_defines.ExactWrite(writer, register_msg)

		while True:
			try:
				response = await dsc_defines.ExactRead(reader)
				if response is None:
					print("response is none, break")
					break
				msg_type = struct.unpack('!I', response[0:4])[0]
				if msg_type == dsc_defines.ResponseType.BcTargetHash.value:
					target_hash = response[4:36]
					block_len = struct.unpack('!I', response[36:40])[0]
					self.OnReceiveTargetHash(target_hash, block_len)
			except asyncio.CancelledError:
				writer.close()
				await writer.wait_closed()
				break
	
	async def ConnectToMetronome(self):
		mn_config = self.m_config["Metronome"]
		ip = mn_config["ip"]
		port = int(mn_config["port"])
		reader, writer = None, None
		while True:
			try:
				reader, writer = await asyncio.open_connection(ip, port)
				break
			except:
				await asyncio.sleep(1)
				continue
		self.m_mn_writer = writer
		await dsc_defines.ExactWrite(writer, struct.pack('!I', dsc_defines.RequestType.ValidatorMnRegister.value))


		try:
			while True:
				response = await dsc_defines.ExactRead(reader)
				if response is None:
					break
				msg_type = struct.unpack('!I', response[0:4])[0]
				if msg_type == dsc_defines.ResponseType.MetronomeValidatorApproved.value:
					nonce_recv = struct.unpack('!Q', response[4:12])[0]
					if nonce_recv == self.m_nonce:
						await self.GrabTransactions()
				elif msg_type == dsc_defines.ResponseType.MetronomeDifficulty.value:
					self.m_difficulty = struct.unpack('!H', response[4:6])[0]
					LogMsg("difficulty changed to {}".format(self.m_difficulty))
					stop_all = struct.unpack('!B', response[6:7])[0]
					if stop_all:
						with self.m_work_lock:
							self.m_stop_working_thread = True
		except asyncio.CancelledError:
			writer.close()
			await writer.wait_closed()
	
	async def GrabTransactions(self):
		# get transactions from pool
		if self.m_pool_writer:
			message = struct.pack('!I', dsc_defines.RequestType.ValidatorPoolGrabTransactions.value)
			# 16B
			message += self.m_fingerprint.bytes
			await dsc_defines.ExactWrite(self.m_pool_writer, message) 
		else:
			await self.SendNewBlock(b'')

	async def SendNewBlock(self, transaction_msg):
		# create new block and sent it to metronome
		"""
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
		block = {
			'version': 1,
			'previous_block_hash': self.m_target_hash,
			'block_id': self.m_block_len + 1,
			'timestamp': int(time.time()),
			'difficulty_target': self.m_difficulty,
			'nonce': self.m_nonce,
			'transactions': []
		}
		msg = struct.pack('!I', dsc_defines.RequestType.ValidatorBcNewBlock.value)
		# 16B
		msg += self.m_fingerprint.bytes
		# pubkey 32B
		msg += self.m_public_key_bytes
		# block bytes
		transaction_size = len(transaction_msg) // dsc_defines.TRANSACTION_BYTES
		msg += dsc_defines.BlockDictToBytes(block, transaction_size)
		if (transaction_size > 0):
			# transaction bytes
			msg += transaction_msg
		# send new block to metronome
		await dsc_defines.ExactWrite(self.m_bc_writer, msg)

	async def ConnectToPool(self):
		config = self.m_config["Pool"]
		ip = config["ip"]
		port = int(config["port"])
		reader, writer = None, None
		while True:
			try:
				reader, writer = await asyncio.open_connection(ip, port)
				break
			except:
				await asyncio.sleep(1)
				continue
		self.m_pool_writer = writer
		register_msg = struct.pack('!I', dsc_defines.RequestType.ValidatorPoolRegister.value)
		register_msg += self.m_fingerprint.bytes
		await dsc_defines.ExactWrite(writer, register_msg)

		while True:
			try:
				response = await dsc_defines.ExactRead(reader)
				if response is None:
					break
				msg_type = struct.unpack('!I', response[0:4])[0]
				if msg_type == dsc_defines.ResponseType.PoolValidatorGrabTransactions.value:
					await self.SendNewBlock(response[4:])
			except asyncio.CancelledError:
				writer.close()
				await writer.wait_closed()
				break

	async def RunAllTask(self):
		await asyncio.gather(self.ConnectToPool(), self.ConnectToBlockchain(), self.ConnectToMetronome())

if __name__ == "__main__":
	validator = GetValidator()
	asyncio.run(validator.RunAllTask())
	
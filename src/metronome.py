#!/usr/bin/env python3

import dsc_defines
import struct
import asyncio
import blake3

g_Metronome = None

def GetMetronome():
	global g_Metronome
	if g_Metronome is None:
		g_Metronome = CMetronome()
	return g_Metronome


class CMetronome(object):

	def __init__(self):
		self.LoadConfig()
		self.m_bc_writer = None
		self.m_difficulty = dsc_defines.BLOCKCHAIN_DIFFICULTY
		self.m_validator_writers = []
		self.m_block_len = 0

		self.m_target_hash = None
		# validator provide nonce and a hash. If approved the hash is then sent to blockchain
		self.m_winner_info = None
		self.m_winner_count = 0
		self.m_new_block_bytes = None

	def LoadConfig(self):
		config = dsc_defines.LoadConfig()
		self.m_config = config
		pool_config = config['Metronome']
		self.m_port = int(pool_config['port'])
	
	def GetPort(self):
		return self.m_port

	async def JustSendDifficulty(self, writer):
		message = struct.pack('!I', dsc_defines.ResponseType.MetronomeDifficulty.value)
		message += struct.pack('!H', self.m_difficulty)
		# don't stop worker
		message += struct.pack('!B', 0)
		await dsc_defines.ExactWrite(writer, message)

	async def ApproveValidator(self, writer):
		message = struct.pack('!I', dsc_defines.ResponseType.MetronomeValidatorApproved.value)
		message += struct.pack('!Q', self.m_winner_info[2])
		await dsc_defines.ExactWrite(writer, message)

	async def BroadcastDifficulty(self, stop_worker):
		message = struct.pack('!I', dsc_defines.ResponseType.MetronomeDifficulty.value)
		message += struct.pack('!H', self.m_difficulty)
		# stop all pow workers
		if stop_worker:
			message += struct.pack('!B', 1)
		else:
			message += struct.pack('!B', 0)

		send_tasks = []
		for writer in self.m_validator_writers:
			send_tasks.append(dsc_defines.ExactWrite(writer, message))
		if send_tasks:
			await asyncio.gather(*send_tasks)

	async def AsyncHandleClient(self, reader, writer):
		request = None
		response = ""
		try:
			while True:
				request = await dsc_defines.ExactRead(reader)
				if request is None or request == 'quit':
					break
				msg_type = struct.unpack('!I', request[0:4])[0]
				# print("received message:", len(request), msg_type)
				if msg_type == dsc_defines.RequestType.ValidatorMnRegister.value:
					self.m_validator_writers.append(writer)
					await self.JustSendDifficulty(writer)
				elif msg_type == dsc_defines.RequestType.BcMetronomeRegister.value:
					self.m_bc_writer = writer
					self.m_target_hash = request[4:28]
					self.m_block_len = struct.unpack('!I', request[28:32])[0]
				elif msg_type == dsc_defines.ResponseType.BcTargetHash.value:
					self.m_target_hash = request[4:28]
					self.m_block_len = struct.unpack('!I', request[28:32])[0]
					# reset winner_info
					self.m_winner_info = None
					self.m_winner_count = 0
				elif msg_type == dsc_defines.RequestType.ValidatorMnFoundNonce.value:
					self.m_winner_count += 1
					if self.m_winner_info is not None:
						# some other validator already found the nonce
						# print("nonce already found, return")
						message = struct.pack('!I', dsc_defines.ResponseType.MetronomeValidatorNotApproved.value)
						await dsc_defines.ExactWrite(writer, message)
						continue
					# fingerprint, public key, nonce
					fingerprint_bytes = request[4:20]
					public_key_bytes = request[20:52]
					nonce_recv = struct.unpack('!Q', request[52:60])[0]
					# verify nonce
					blake3_param = dsc_defines.ValidatorFormBlake3Param(fingerprint_bytes, public_key_bytes, nonce_recv)
					generated_hash = blake3.blake3(blake3_param).digest(length=dsc_defines.BLOCKCHAIN_VALIDATE_HASH_SIZE)
					generated_hash_bits = dsc_defines.GetFirstNBits(generated_hash, self.m_difficulty)
					valid_bits = dsc_defines.GetFirstNBits(self.m_target_hash, self.m_difficulty)
					if valid_bits == generated_hash_bits:
						#self.InsertBlock(self.m_target_nonce)
						self.m_winner_info = (fingerprint_bytes, public_key_bytes, nonce_recv)
						await self.ApproveValidator(writer)
				elif msg_type == dsc_defines.RequestType.ValidatorBlockRequest.value:
					await dsc_defines.ExactWrite(writer, response)
	
		except asyncio.CancelledError:
			pass

		writer.close()
		await writer.wait_closed()

	async def RunServer(self):
		ip = self.m_config['Metronome']['ip']
		server = await asyncio.start_server(self.AsyncHandleClient, ip, self.m_port)
		addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
		print(f"Metronome serving on {addrs}")
		try:
			async with server:
				await server.serve_forever()
		except:
			print("RunServer execption")
			if server:
				server.close()
				await server.wait_closed()

	def CreateEmptyBlock(self):
		import time
		block_size = self.m_block_len
		block = {}
		block['version'] = 1
		block['previous_block_hash'] = self.m_target_hash
		block['block_id'] = block_size + 1
		block['timestamp'] = int(time.time())
		block['difficulty_target'] = self.m_difficulty
		block['nonce'] = 0
		block['transactions'] = []
		return dsc_defines.BlockDictToBytes(block, 0)

	# every 6 seconds tell blockchain to insert block, adjust difficulty, and broadcast to all validators
	async def NotifyBlockchain(self):
		while True:
			# dynamic difficulty
			if self.m_winner_count >= len(self.m_validator_writers):
				self.m_difficulty += 1
				await self.BroadcastDifficulty(True)
			elif self.m_winner_count < len(self.m_validator_writers) / 2:
				self.m_difficulty = max(1, self.m_difficulty - 1)
				await self.BroadcastDifficulty(True)

			message = struct.pack('!I', dsc_defines.ResponseType.MetronomeBcBeat.value)
			if self.m_bc_writer:
				# some validator got the nonce
				if self.m_winner_info:
					message += struct.pack('!B', 0)  # is empty = 0, represent validator found nonce
					await dsc_defines.ExactWrite(self.m_bc_writer, message)
					self.m_winner_info = None
					self.m_winner_info = 0
				else:	# no validator got the nonce
					message += struct.pack('!B', 1)
					message += self.CreateEmptyBlock()
					await dsc_defines.ExactWrite(self.m_bc_writer, message)

			await asyncio.sleep(dsc_defines.NEW_HASH_INTERVAL)

	async def RunAllTask(self):
		await asyncio.gather(self.RunServer(), self.NotifyBlockchain())
	
if __name__ == "__main__":
	pool = GetMetronome()
	asyncio.run(pool.RunAllTask())
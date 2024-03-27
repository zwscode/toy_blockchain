#!/usr/bin/env python3

import dsc_defines
import struct
import asyncio
import blake3
import os
import time
from collections import deque
from dsc_defines import LogMsg

g_Blockchain = None

def GetBlockchain():
	global g_Blockchain
	if g_Blockchain is None:
		g_Blockchain = CBlockchain()
	return g_Blockchain

class CBlockchain(object):

	def __init__(self):
		self.m_difficulty = dsc_defines.BLOCKCHAIN_DIFFICULTY
		self.LoadConfig()
		self.m_mn_writer = None
		self.m_saved_new_block = None

	def LoadConfig(self):
		config = dsc_defines.LoadConfig()
		pool_config = config['Blockchain']
		self.m_config = config
		self.m_port = int(pool_config['port'])
		self.m_validators = {}
		self.m_pool_writer = None
		self.m_blocks = []
		self.m_target_nonce = 0
		self.m_max_trans_per_block = dsc_defines.MAX_TRANSACTION_PER_BLOCK - 1

		# cache dict for checking wallet balance
		self.m_balance_dict = {}

		# record the transaction state of all transactions
		# id, status, timestamp, coin, source, destination
		self.m_trans_info = {}

		# insert genesis block
		self.m_blocks.append(self.GenerateFristBlock())

		self.m_confirmed_transactions = []
		self.m_rejected_transactions = []

	def NotifyPoolTransactions(self):
		if self.m_pool_writer is None:
			return
		
		message = struct.pack('!I', dsc_defines.ResponseType.BcPoolTransactionsResult.value)
		message += struct.pack('!I', len(self.m_confirmed_transactions))
		message += struct.pack('!I', len(self.m_rejected_transactions))
		for trans_id in self.m_confirmed_transactions:
			message += trans_id
		for trans_id in self.m_rejected_transactions:
			message += trans_id

		self.m_confirmed_transactions.clear()
		self.m_rejected_transactions.clear()
		dsc_defines.SyncExactWrite(self.m_pool_writer, message)
		

	def GenerateFristBlock(self):
		"""
		Block (128B header + 128B*#trans)  multiple transactions will be stored in a block on the blockchain
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
		block = {}
		block['version'] = 1
		block['previous_block_hash'] = bytes(24)
		block['block_id'] = 0
		block['timestamp'] = int(time.time())
		block['difficulty_target'] = self.m_difficulty
		block['nonce'] = 0
		block['transactions'] = []
		return dsc_defines.BlockDictToBytes(block, 0)

	def GetLastBlockHash(self):
		import hashlib
		return bytes.fromhex(hashlib.sha256(self.m_blocks[-1]).hexdigest())
  
	def GetBalance(self, public_key_bytes):
		if (public_key_bytes == bytes(32)):
			return 99999999.0
		return self.m_balance_dict.get(public_key_bytes, 0.0)

	def RewardValidator(self, public_key_bytes):
		'''
		Transaction (128B)
			Sender Public Address (32B)
			Recipient Public Address (32B)
			Value (unsigned double, 8B)
			Timestamp (signed integer 8B)
			Transaction ID (16B)
			Signature (32B)
		'''
		import uuid
		trans = {
			'sender': bytes(32),
			'recipient': public_key_bytes,
			'value': dsc_defines.BLOCKCHAIN_REWARD,
			'timestamp': int(time.time()),
			'id': uuid.uuid4().bytes,
			'signature': bytes(32)
		}
		self.ExecuteTransaction(trans)

	def ExecuteTransaction(self, trans):
		"""
		Transaction (128B)
			Sender Public Address (32B)
			Recipient Public Address (32B)
			Value (unsigned double, 8B)
			Timestamp (signed integer 8B)
			Transaction ID (16B)
			Signature (32B)
		"""
		sender_is_not_bc = trans['sender'] != bytes(32)
		if trans['sender'] not in self.m_balance_dict and sender_is_not_bc:
			return False
		sender_balance = self.GetBalance(trans['sender'])
		if sender_balance < trans['value']:
			return False
		# can't send negative or zero value
		if trans['value'] <= 0.0:
			return False
		if sender_is_not_bc:
			self.m_balance_dict[trans['sender']] -= trans['value']
		self.m_balance_dict[trans['recipient']] = self.m_balance_dict.get(trans['recipient'], 0.0) + trans['value']
		return True

	async def OnQueryAllTransactions(self, writer, request):
		pubkey = request[4:36]
		trans_list = []
		for trans_id, trans_info in self.m_trans_info.items():
			if pubkey == trans_info['sender'] or pubkey == trans_info['recipient']:
				trans_list.append(trans_info)
		trans_list.sort(key=lambda x: x['timestamp'])
		response = struct.pack('!I', dsc_defines.ResponseType.BcWalletTransactions.value)
		response += struct.pack('!I', len(trans_list))
		for trans in trans_list:
			response += dsc_defines.TransactionDictToBytes(trans)
			# state is not considered in TransactionDictToBytes/ParseTransaction pair
			response += struct.pack('!H', trans['state'])
		await dsc_defines.ExactWrite(writer, response)

	# save the new block data, wait for metronome heartbeat to insert it
	def SaveNewBlockForMetronomeBeat(self, request):
		self.m_saved_new_block = request

	# only insert the new block received from validator when metronome sends the heartbeat
	def InsertSavedNewBlock(self):
		import uuid
		if not self.m_saved_new_block:
			assert False, "m_saved_new_block is None"
			return
		request = self.m_saved_new_block
		self.m_saved_new_block = None
		fingerprint = request[4:20]
		pubkey = request[20:52]
		self.RewardValidator(pubkey)
		block_bytes = request[52:]
		self.m_blocks.append(block_bytes)

		# parse all transactions
		block_size = struct.unpack('!I', block_bytes[0:4])[0]
		trans_bytes = dsc_defines.TRANSACTION_BYTES
		transaction_num = (block_size - dsc_defines.BLOCK_HEADER_BYTES) // trans_bytes
		transaction_bytes = block_bytes[dsc_defines.BLOCK_HEADER_BYTES:]
		trans_result = False
		trans_state = dsc_defines.TransactionState.confirmed.value
		self.m_confirmed_transactions.clear()
		self.m_rejected_transactions.clear()
		for i in range(transaction_num):
			start_idx = trans_bytes * i
			trans_info = dsc_defines.ParseTransaction(transaction_bytes[start_idx: start_idx + trans_bytes])
			trans_result = self.ExecuteTransaction(trans_info)
			if (trans_result):
				trans_state = dsc_defines.TransactionState.confirmed.value
				self.m_confirmed_transactions.append(trans_info['id'])
			else:
				trans_state = dsc_defines.TransactionState.failed.value
				self.m_rejected_transactions.append(trans_info['id'])
			trans_info['state'] = trans_state
			self.m_trans_info[trans_info['id']] = trans_info

		fingerprint_str = str(uuid.UUID(bytes=fingerprint))
		LogMsg("New block received from validator {}, Block {} hash {}".format(fingerprint_str, len(self.m_blocks), dsc_defines.Base58Str(self.GetLastBlockHash())))
		self.NotifyPoolTransactions()

	async def AsyncHandleClient(self, reader, writer):
		request = None
		response = ""
		try:
			while True:
				request = await dsc_defines.ExactRead(reader)
				if request is None:
					break
				msg_type = struct.unpack('!I', request[0:4])[0]
				#print("message_received:", len(request), msg_type)
				if msg_type == dsc_defines.RequestType.WalletBalance.value:
					public_key_bytes = request[4:36]
					response = struct.pack('!I', dsc_defines.ResponseType.WalletBalance.value)
					balance = self.GetBalance(public_key_bytes)
					response += struct.pack('!d', balance)
					await dsc_defines.ExactWrite(writer, response)
				elif msg_type == dsc_defines.RequestType.WalletBcTransactions.value:
					await self.OnQueryAllTransactions(writer, request)
				elif msg_type == dsc_defines.RequestType.ValidatorBcRegister.value:
					fingerprint = request[4:20]
					self.m_validators[fingerprint] = writer
					msg = self.GenerateTargetHashMsg()
					await dsc_defines.ExactWrite(writer, msg)
				elif msg_type == dsc_defines.RequestType.ValidatorBcNewBlock.value:
					self.SaveNewBlockForMetronomeBeat(request)
				elif msg_type == dsc_defines.RequestType.PoolBcRegister.value:
					self.m_pool_writer = writer
				elif msg_type == dsc_defines.RequestType.PoolBcTransactionState.value:
					trans_id = request[4:20]
					response = struct.pack('!I', dsc_defines.ResponseType.BcPoolTransState.value)
					trans_info = self.m_trans_info.get(trans_id)
					trans_state = dsc_defines.TransactionState.unknown.value
					if trans_info:
						trans_state = trans_info['state']
					response += struct.pack('!I', trans_state)
					await dsc_defines.ExactWrite(writer, response)
		except asyncio.CancelledError:
			print("client cancelled")
			pass

		# remove writer
		for fingerprint, writer_in in self.m_validators.items():
			if writer_in == writer:
				del self.m_validators[fingerprint]
				break
		writer.close()

	async def RunServer(self):
		server = None
		ip = self.m_config["Blockchain"]["ip"]
		server = await asyncio.start_server(self.AsyncHandleClient, ip, self.m_port)
		addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
		print(f"Blockchain serving on {addrs}")
		try:
			async with server:
				await server.serve_forever()
		except:
			print("RunServer execption")
			if server:
				server.close()
				await server.wait_closed()

	def GenerateTargetHashMsg(self):
		message = struct.pack('!I', dsc_defines.ResponseType.BcTargetHash.value)
		message += self.GetLastBlockHash()
		message += struct.pack('!I', len(self.m_blocks))
		return message

	async def BroadcastTargetHash(self):
		send_tasks = []
		
		# use last block's hash as target hash 
		message = self.GenerateTargetHashMsg()
		send_tasks.append(dsc_defines.ExactWrite(self.m_mn_writer, message))
		for validator_writer in self.m_validators.values():
			send_tasks.append(dsc_defines.ExactWrite(validator_writer, message))
		
		if (len(send_tasks)):
			try:
				await asyncio.gather(*send_tasks)
			except:
				pass
		

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
		register_msg = struct.pack('!I', dsc_defines.RequestType.BcMetronomeRegister.value)
		register_msg += self.GetLastBlockHash()
		register_msg += struct.pack('!I', len(self.m_blocks))
		await dsc_defines.ExactWrite(writer, register_msg)

		while True:
			try:
				response = await dsc_defines.ExactRead(reader)
				if not response:
					break
				msg_type = struct.unpack('!I', response[0:4])[0]
				if msg_type == dsc_defines.ResponseType.MetronomeBcBeat.value:
					is_empty_block = struct.unpack('!B', response[4:5])[0]
					# handle new block from metronome
					if is_empty_block:
						block_bytes = response[5:]
						self.m_blocks.append(block_bytes)
						LogMsg("New block received from metronome, Block {} hash {}".format(len(self.m_blocks), dsc_defines.Base58Str(self.GetLastBlockHash())))
					else:
						self.InsertSavedNewBlock()
					await self.BroadcastTargetHash()
			except asyncio.CancelledError:
				writer.close()
				await writer.wait_closed()
				break

	async def RunAllTask(self):
		await asyncio.gather(self.ConnectToMetronome(), self.RunServer())

if __name__ == "__main__":
	bc = GetBlockchain()
	asyncio.run(bc.RunAllTask())
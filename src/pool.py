#!/usr/bin/env python3

import dsc_defines
import asyncio
import struct
from collections import deque
from dsc_defines import LogMsg


g_Pool = None

def GetPool():
	global g_Pool
	if g_Pool is None:
		g_Pool = CPool()
	return g_Pool


class CPool(object):

	def __init__(self):
		self.LoadConfig()
		self.m_bc_writer = None

		self.m_submitted_transactions = deque([])
		self.m_submited_lookup = {}
		self.m_unconfirmed_transactions = deque([])
		self.m_unconfirmed_lookup = {}

		# used to cache transaction results for walltet transaction query
		self.m_trans_state = {}
		
		self.m_validator_writers = []

	def LoadConfig(self):
		config = dsc_defines.LoadConfig()
		self.m_config = config
		pool_config = config['Pool']
		self.m_port = int(pool_config['port'])
	
	def GetPort(self):
		return self.m_port
	
	def OnSubmitTransaction(self, trans_id, transaction):
		self.m_submitted_transactions.append((trans_id, transaction))
		self.m_submited_lookup[trans_id] = transaction

	def GetTransactionsForValidator(self):
		counter = 0
		trans_list = []
		tras_ids = []
		for i in range(dsc_defines.MAX_TRANSACTION_PER_BLOCK - 1):
			if len(self.m_submitted_transactions) == 0:
				break
			trans_id, transaction_bytes = self.m_submitted_transactions.popleft()
			del self.m_submited_lookup[trans_id]
			
			self.m_unconfirmed_lookup[trans_id] = transaction_bytes
			self.m_unconfirmed_transactions.append((trans_id, transaction_bytes))
			trans_list.append(transaction_bytes)
			counter += 1
			tras_ids.append(trans_id)
		return trans_list

	def OnRecvTransactionsResult(self, response):
		num_confirmed = struct.unpack('!I', response[4:8])[0]
		num_failed = struct.unpack('!I', response[8:12])[0]
		del_trans = set([])
		for i in range(num_confirmed):
			trans_id = response[12 + i * 16: 28 + i * 16]
			self.m_trans_state[trans_id] = dsc_defines.TransactionState.confirmed.value
			if trans_id in self.m_unconfirmed_lookup:
				del self.m_unconfirmed_lookup[trans_id]
				del_trans.add(trans_id)
		start_idx = 12 + num_confirmed * 16

		for i in range(num_failed):
			trans_id = response[start_idx + i * 16: start_idx + 16 + i * 16]
			self.m_trans_state[trans_id] = dsc_defines.TransactionState.failed.value
			if trans_id in self.m_unconfirmed_lookup:
				del self.m_unconfirmed_lookup[trans_id]
				del_trans.add(trans_id)

		# delete all trans_infos in m_unconfirmed_transactions
		del_idx = []
		for idx, trans_info in enumerate(self.m_unconfirmed_transactions):
			if trans_info[0] in del_trans:
				del_idx.append(idx)
		for idx in reversed(del_idx):
			del self.m_unconfirmed_transactions[idx]

	async def QueryBlockchainTransactionState(self, transaction_id):
		message = struct.pack('!I', dsc_defines.RequestType.PoolBcTransactionState.value)
		message += transaction_id
		await dsc_defines.ExactWrite(self.m_bc_writer, message)

	async def RespondGrabTransactions(self, writer, fingerprint):
		message = struct.pack('!I', dsc_defines.ResponseType.PoolValidatorGrabTransactions.value)
		transaction_list = self.GetTransactionsForValidator()
		for transaction_bytes in transaction_list:
			message += transaction_bytes
		LogMsg("validator {} grabbed {} transactions".format(dsc_defines.FingerprintBytesToStr(fingerprint), len(transaction_list)))
		await dsc_defines.ExactWrite(writer, message)

	async def AsyncHandleClient(self, reader, writer):
		request = None
		response = ""
		try:
			while True:
				request = await dsc_defines.ExactRead(reader)
				if request is None or request == 'quit':
					break
				msg_type = struct.unpack('!I', request[0:4])[0]
				#print("message_received:", len(request))
				if msg_type == dsc_defines.RequestType.WalletSend.value:
					'''
					Transaction (128B)
						Sender Public Address (32B)
						Recipient Public Address (32B)
						Value (unsigned double, 8B)
						Timestamp (signed integer 8B)
						Transaction ID (16B)
						Signature (32B)
					'''
					# sender_public_key = request[4:36]
					# target_public_key = request[36:68]
					# amount = struct.unpack('!d', request[68:76])[0]
					# time_val = struct.unpack('!Q', request[76:84])[0]
					transaction_id = request[84:100]
					self.OnSubmitTransaction(transaction_id, request[4:])
					response = struct.pack('!I', dsc_defines.ResponseType.WalletTransactionSubmitted.value)
					response += transaction_id
					await dsc_defines.ExactWrite(writer, response)
				elif msg_type == dsc_defines.RequestType.WalletPoolTransactionState.value:
					transaction_id = request[4:20]
					trans_state = None
					if transaction_id in self.m_submited_lookup:
						trans_state = dsc_defines.TransactionState.submited.value
					elif transaction_id in self.m_unconfirmed_lookup:
						trans_state = dsc_defines.TransactionState.unconfirmed.value
					elif transaction_id in self.m_trans_state:
						trans_state = self.m_trans_state[transaction_id]
					else:
						await self.QueryBlockchainTransactionState(transaction_id)
						trans_state = self.m_trans_state[transaction_id]
					response = struct.pack('!I', dsc_defines.ResponseType.PoolWalletTransactionState.value)
					response += transaction_id
					response += struct.pack('!I', trans_state)
					await dsc_defines.ExactWrite(writer, response)
				elif msg_type == dsc_defines.RequestType.ValidatorPoolRegister.value:
					fingerprint = request[4:20]
					self.m_validator_writers.append(writer)
					LogMsg("validator {} registered".format(dsc_defines.FingerprintBytesToStr(fingerprint)))
				elif msg_type == dsc_defines.RequestType.ValidatorPoolGrabTransactions.value:
					finnngerprint = request[4:20]
					await self.RespondGrabTransactions(writer, finnngerprint)


		except asyncio.CancelledError:
			pass

		writer.close()
		await writer.wait_closed()

	async def RunServer(self):
		ip = self.m_config['Pool']['ip']
		server = await asyncio.start_server(self.AsyncHandleClient, ip, self.m_port)
		addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
		print(f"Pool serving on {addrs}")
		try:
			async with server:
				await server.serve_forever()
		except:
			print("RunServer execption")
			if server:
				server.close()
				await server.wait_closed()

	async def RunAllTask(self):
		await asyncio.gather(self.RunServer(), self.ConnectToBlockchain())

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

		self.m_bc_writer = writer
		await dsc_defines.ExactWrite(writer, struct.pack('!I', dsc_defines.RequestType.PoolBcRegister.value))

		while True:
			try:
				response = await dsc_defines.ExactRead(reader)
				if response is None:
					break
				msg_type = struct.unpack('!I', response[0:4])[0]
				if msg_type == dsc_defines.ResponseType.BcPoolTransState.value:
					trans_id = response[4:20]
					trans_state = struct.unpack('!I', response[20:24])[0]
					self.m_trans_state[trans_id] = trans_state
				elif msg_type == dsc_defines.ResponseType.BcPoolTransactionsResult.value:
					self.OnRecvTransactionsResult(response)
				else:
					pass

			except asyncio.CancelledError:
				writer.close()
				await writer.wait_closed()
				break
	
if __name__ == "__main__":
	pool = GetPool()
	asyncio.run(pool.RunAllTask())

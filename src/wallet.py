#!/usr/bin/env python3

import dsc_defines
import hashlib
import os
import base58
import ecdsa
import asyncio
import struct
import uuid
import time

from dsc_defines import LogMsg

g_Wallet = None


def GetWallet():
	global g_Wallet
	if g_Wallet is None:
		g_Wallet = CWallet()
	return g_Wallet

class CWallet(object):
	wallet_file_name = "dsc_key.yaml"

	def __init__(self):
		self.m_is_init = False
		self.m_public_key = None
		self.m_private_key = None
		self.m_public_key_base58 = ""
		self.m_private_key_base58 = ""
		self.LoadConfig()

	def LoadConfig(self):
		config = dsc_defines.LoadConfig()
		self.m_config = config
		pool_config = config['Pool']
		self.m_pool_ip = pool_config['ip']
		self.m_pool_port = int(pool_config['port'])

	def CreateWallet(self):
		import yaml
		if (self.m_is_init):
			LogMsg("Wallet already loaded.")
			return
		current_dir = os.path.dirname(os.path.abspath(__file__))
		wallet_path = os.path.join(current_dir, CWallet.wallet_file_name)
		if os.path.isfile(wallet_path):
			LogMsg("Wallet already exists at dsc-key.yaml, wallet create aborted")
			return
		ecdsa_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
		self.m_private_key = hashlib.sha256(ecdsa_private_key.to_string()).hexdigest()
		public_key = hashlib.sha256(self.m_private_key.encode('utf-8')).hexdigest()
		self.m_public_key = public_key

		private_key_base58 = None
		public_key_base58 = None
		wallet_private_key_cfg = {
			'Wallet': {}
		}
		bytes_str = bytes.fromhex(self.m_private_key)
		base58_str = base58.b58encode_check(bytes_str)
		private_key_base58 = base58_str.decode("utf-8")
		wallet_private_key_cfg['Wallet']['private_key'] = private_key_base58
		yaml.dump(wallet_private_key_cfg, open(wallet_path, 'w'), default_flow_style=False)

		permission = 0o400
		os.chmod(wallet_path, permission)

		bytes_str = bytes.fromhex(self.m_public_key)
		base58_str = base58.b58encode_check(bytes_str)
		public_key_base58 = base58_str.decode("utf-8")
		self.m_config['Wallet'] = {}
		self.m_config['Wallet']['public_key'] = public_key_base58
		cfg_path = os.path.join(current_dir, dsc_defines.config_file_name)
		yaml.dump(self.m_config, open(cfg_path, 'w'), default_flow_style=False)
		self.m_is_init = True
		LogMsg("DSC Public Address: " + private_key_base58)
		LogMsg("DSC Private Address: " + public_key_base58)

	def LoadWallet(self):
		import yaml
		if self.m_is_init:
			return True
		error_msg = """Error in finding key information, ensure that dsc-config.yaml and dsc-key.yaml exist and that they contain the correct information. You may need to run \"./dsc.py wallet create\""""
		cur_dir = os.path.dirname(os.path.abspath(__file__))
		wallet_file_path = os.path.join(cur_dir, CWallet.wallet_file_name)
		if not os.path.isfile(wallet_file_path):
			LogMsg(error_msg)
			return False
		if not os.path.isfile(os.path.join(cur_dir, dsc_defines.config_file_name)):
			LogMsg(error_msg)
			return False

		config = None
		with open(wallet_file_path, 'r') as f:
			config = yaml.safe_load(f)
		self.m_private_key_base58 = config['Wallet']['private_key']
		private_key_bytes = base58.b58decode_check(self.m_private_key_base58)
		self.m_private_key = bytes.hex(private_key_bytes)

		# public key is in dsc_config.yaml
		self.m_public_key_base58 = self.m_config['Wallet']['public_key']
		self.m_public_key = bytes.hex(base58.b58decode_check(self.m_public_key_base58))

		self.m_is_init = True
		return True

	def ShowKey(self):
		if not self.m_is_init and not self.LoadWallet():
			LogMsg("wallet not created")
			return
		LogMsg("Reading dsc-config.yaml and dsc-key.yaml...")
		LogMsg("DSC Public Address: " + self.m_public_key_base58)
		LogMsg("DSC Private Address: " + self.m_private_key_base58)

	def PrintPublicKey(self):
		if not self.m_is_init and not self.LoadWallet():
			LogMsg("wallet not created")
			return
		print(self.m_public_key_base58)

	def PrintPrivateKey(self):
		if not self.m_is_init and not self.LoadWallet():
			LogMsg("wallet not created")
			return
		print(self.m_private_key_base58)

	def CmdQueryTransactionState(self, transaction_str):
		if not self.m_is_init and not self.LoadWallet():
			LogMsg("wallet not created")
			return
		asyncio.run(self.SendQueryTransactionState(transaction_str))

	def CmdQueryAllTransactions(self):
		if not self.m_is_init and not self.LoadWallet():
			LogMsg("wallet not created")
			return
		asyncio.run(self.SendQueryAllTransactions())

	def CreateTransactionMsg(self, amount, target_adddress, trans_id):
		# mesasge type 4B
		message = struct.pack('!I', dsc_defines.RequestType.WalletSend.value)
		# sender pubkey
		message += bytes.fromhex(self.m_public_key)
		target_pub_key = None
		try:
			target_pub_key = dsc_defines.Base58ToBytes(target_adddress)
		except:
			LogMsg("invalid recipient address")
			return
		message += target_pub_key
		# Value 8B
		trans_value = float(amount)
		message += struct.pack('!d', trans_value)
		# Timestamp 8B
		message += struct.pack('!Q', int(time.time()))
		# Transaction ID 16B
		trans_id_bytes = trans_id
		message += trans_id_bytes
		# Signature 32B
		# as instructed in ProjectPhase1.pdf, we should generate public key from private key using SHA256
		# however, we can't use public key to verify signiture, because the private key and public key are not a pair generated by crypotographic algorithms
		# So I just put the public key here as the signiture
		message += bytes.fromhex(self.m_public_key)
		return message

	def CreateTransactionId(self):
		return uuid.uuid4().bytes

	def CmdSendTransaction(self, amount, target_base58):
		import time
		if not self.m_is_init and not self.LoadWallet():
			LogMsg("wallet not created")
			return
		'''
		Transaction (128B)
			Sender Public Address (32B)
			Recipient Public Address (32B)
			Value (unsigned double, 8B)
			Timestamp (signed integer 8B)
			Transaction ID (16B)
			Signature (32B)
		'''
		message = self.CreateTransactionMsg(amount, target_base58, self.CreateTransactionId())
		asyncio.run(self.SendTransaction(message))

	# batch send transactions, do not wait for last transaction to be confirmed to send the next one
	def CmdSendThroughputTest(self, transaction_num, address_str):
		assert transaction_num > 0, "transaction_num must be greater than 0"
		assert address_str, "public_addresses must not be empty"
		if not self.m_is_init and not self.LoadWallet():
			LogMsg("wallet not created")
			return
		public_addresses = address_str.split(' ')
		transaction_msg_list = []
		trans_id_set = set([])
		for i in range(transaction_num):
			trans_id = self.CreateTransactionId()
			trans_id_set.add(trans_id)
			address = public_addresses[i % len(public_addresses)]
			msg = self.CreateTransactionMsg(0.01, address, trans_id)
			assert msg, "msg is None"
			transaction_msg_list.append(msg)
		asyncio.run(self.SendThroughputTest(transaction_msg_list, trans_id_set))

	def GenerateQueryTransactionStateMsg(self, trans_id):
		message = struct.pack('!I', dsc_defines.RequestType.WalletPoolTransactionState.value)
		message += trans_id
		return message

	async def SendQueryTransactionState(self, transaction_str):
		trans_id = dsc_defines.Base58ToBytes(transaction_str)
		reader, writer = await asyncio.open_connection(self.m_pool_ip, self.m_pool_port)
		message_bytes = self.GenerateQueryTransactionStateMsg(trans_id)
		await dsc_defines.ExactWrite(writer, message_bytes)

		response = await dsc_defines.ExactRead(reader)
		message_type = struct.unpack('!I', response[0:4])[0]
		if message_type == dsc_defines.ResponseType.PoolWalletTransactionState.value:
			trans_id_recv = response[4:20]
			trans_str = dsc_defines.Base58Str(trans_id_recv)
			transaction_state = struct.unpack('!I', response[20:24])[0]
			state_str = dsc_defines.TRANS_STATE_VAL_TO_STR[transaction_state]
			LogMsg("Transaction {} status [{}]".format(trans_str, state_str))

	async def SendQueryAllTransactions(self):
		# BcWalletTransactions
		config = self.m_config
		blockchain_config = config['Blockchain']
		ip = blockchain_config['ip']
		port = int(blockchain_config['port'])
		reader, writer = await asyncio.open_connection(ip, port)

		# mesasge type 4B
		message = struct.pack('!I', dsc_defines.RequestType.WalletBcTransactions.value)
		message += bytes.fromhex(self.m_public_key)
		await dsc_defines.ExactWrite(writer, message)

		# handle response
		response = await dsc_defines.ExactRead(reader)
		message_type = struct.unpack('!I', response[0:4])[0]
		if message_type == dsc_defines.ResponseType.BcWalletTransactions.value:
			trans_num = struct.unpack('!I', response[4:8])[0]
			trans_bytes = response[8:]
			# trans['state'] takes 2 bytes
			trans_size = dsc_defines.TRANSACTION_BYTES + 2
			for i in range(trans_num):
				trans = dsc_defines.ParseTransaction(trans_bytes[i * trans_size: (i + 1) * trans_size - 2 ])
				trans['state'] = struct.unpack('!H', trans_bytes[(i + 1) * trans_size - 2: (i + 1) * trans_size])[0]
				LogMsg("Transaction #{}, id={}, status={}, timestamp={}, coin={}, source={}, destination={}".format(
					i+1,
					dsc_defines.Base58Str(trans['id']), 
					dsc_defines.TRANS_STATE_VAL_TO_STR.get(trans['state'], 'error'), 
					dsc_defines.TimeStrFromTimestamp(trans['timestamp']),
					trans['value'], 
					dsc_defines.Base58Str(trans['sender']),
					dsc_defines.Base58Str(trans['recipient']))
				)
		else:
			pass
		writer.close()


	async def QueryPoolTransactionStatus(self, trans_id, writer):
		query_bytes = self.GenerateQueryTransactionStateMsg(trans_id)
		await dsc_defines.ExactWrite(writer, query_bytes)

	async def SendTransaction(self, message_bytes):
		reader, writer = None, None
		try:
			reader, writer = await asyncio.open_connection(self.m_pool_ip, self.m_pool_port)
		except:
			LogMsg("failed to connect to pool")
			exit(1)
		await dsc_defines.ExactWrite(writer, message_bytes)
		while True:
			response = await dsc_defines.ExactRead(reader)
			if response is None:
				break
			transaction_state = None
			message_type = struct.unpack('!I', response[0:4])[0]
			if message_type == dsc_defines.ResponseType.WalletTransactionSubmitted.value:
				trans_id_recv = response[4:20]
				LogMsg("Transaction {} submitted to pool".format(dsc_defines.Base58Str(trans_id_recv)))
				await asyncio.sleep(1)
				await self.QueryPoolTransactionStatus(trans_id_recv, writer)
			elif message_type == dsc_defines.ResponseType.PoolWalletTransactionState.value:
				trans_id_recv = response[4:20]
				trans_str = dsc_defines.Base58Str(trans_id_recv)
				transaction_state = struct.unpack('!I', response[20:24])[0]
				state_str = dsc_defines.TRANS_STATE_VAL_TO_STR[transaction_state]
				LogMsg("Transaction {} status [{}]".format(trans_str, state_str))
				if transaction_state == dsc_defines.TransactionState.confirmed.value or \
					transaction_state == dsc_defines.TransactionState.failed.value or \
					transaction_state == dsc_defines.TransactionState.unknown.value:
					break
				await asyncio.sleep(1)
				await self.QueryPoolTransactionStatus(trans_id_recv, writer)
			else:
				print("unknown message type")
				assert False
		
		writer.close()

	async def SendThroughputTest(self, msg_list, trans_id_set):
		import random
		reader, writer = None, None
		try:
			reader, writer = await asyncio.open_connection(self.m_pool_ip, self.m_pool_port)
		except:
			LogMsg("failed to connect to pool")
			exit(1)
		for msg in msg_list:
			# eat the submitted response
			await dsc_defines.ExactWrite(writer, msg)

		for i in range(len(msg_list)):
			await dsc_defines.ExactRead(reader)

		while trans_id_set:
			query_amount = len(trans_id_set)
			query_amount = max(1, query_amount)
			query_amount = min(dsc_defines.MAX_TRANSACTION_PER_BLOCK - 1, query_amount)

			query_list = list(trans_id_set)
			for i in range(query_amount):
				query_trans_id = query_list[i]
				query_msg = self.GenerateQueryTransactionStateMsg(query_trans_id)
				await dsc_defines.ExactWrite(writer, query_msg)

			for i in range(query_amount):
				response = await dsc_defines.ExactRead(reader)
				if response is None:
					break
				msg_type = struct.unpack('!I', response[0:4])[0]
				if msg_type == dsc_defines.ResponseType.PoolWalletTransactionState.value:
					trans_id = response[4:20]
					trans_state = struct.unpack('!I', response[20:24])[0]
					# LogMsg(f"transaction:{dsc_defines.Base58Str(trans_id)} status:{trans_state}")
					if trans_id in trans_id_set:
						if trans_state == dsc_defines.TransactionState.confirmed.value or \
							trans_state == dsc_defines.TransactionState.failed.value or \
							trans_state == dsc_defines.TransactionState.unknown.value:
							trans_id_set.remove(trans_id)
			await asyncio.sleep(0.1)
		writer.close()
		LogMsg("all {} transactions confirmed".format(len(msg_list)))

	def GetBalance(self):
		asyncio.run(self.SendGetBalance())

	async def SendGetBalance(self):
		if not self.m_is_init and not self.LoadWallet():
			print("wallet not created")
			return
		config = self.m_config
		blockchain_config = config['Blockchain']
		ip = blockchain_config['ip']
		port = int(blockchain_config['port'])
		reader, writer = await asyncio.open_connection(ip, port)
		message = struct.pack('!I', dsc_defines.RequestType.WalletBalance.value)
		message += bytes.fromhex(self.m_public_key)
		await dsc_defines.ExactWrite(writer, message)

		response = await dsc_defines.ExactRead(reader)
		message_type = struct.unpack('!I', response[0:4])[0]
		if message_type == dsc_defines.ResponseType.WalletBalance.value:
			balance = struct.unpack('!d', response[4:12])[0]
			dsc_defines.LogMsg(f"DSC Wallet balance: {balance} coins")
		else:
			pass
		writer.close()


#!/usr/bin/env python3

import subprocess
import argparse
import wallet
import os
from dsc_defines import LogMsg

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="dsc: DataSys Coin")
	cmd_subparsers = parser.add_subparsers(dest='command', required=True)

	# help
	help_parser = cmd_subparsers.add_parser('help', help='Help')

	# wallet
	wallet_parser = cmd_subparsers.add_parser('wallet', help='Wallet commands')

	wallet_subparsers = wallet_parser.add_subparsers(dest='wallet_command', required=True)
	wallet_create_parser = wallet_subparsers.add_parser('create', help='Create a new wallet')
	wallet_key_parser = wallet_subparsers.add_parser('key', help='Read and display wallet key')
	wallet_balance_parser = wallet_subparsers.add_parser('balance', help='Check the wallet balance')

	wallet_transaction_parser = wallet_subparsers.add_parser('transaction', help='Check state of one transaction')
	wallet_transaction_parser.add_argument('transaction_id', type=str, help='Transaction ID')
	wallet_transactions_parser = wallet_subparsers.add_parser('transactions', help='Check all the transactions')

	wallet_send_parser = wallet_subparsers.add_parser('send', help='Send coin')
	wallet_send_parser.add_argument('amount', type=float, help='Amount of coin to send')
	wallet_send_parser.add_argument('address', type=str, help='Receiver of the coin')

	wallet_throughput_parser = wallet_subparsers.add_parser('throughput', help='Test throughput')
	wallet_throughput_parser.add_argument('num', type=int, help='Number of transactions to send')
	wallet_throughput_parser.add_argument('address', type=str, help='Receiver of the coin')
	# metronome
	metronome_parser = cmd_subparsers.add_parser('metronome', help='Metronome command')

	# pool
	pool_parser = cmd_subparsers.add_parser('pool', help='Pool command')

	# blockchain
	blockchain_parser = cmd_subparsers.add_parser('blockchain', help='Blockchain command')

	# validator
	validator_parser = cmd_subparsers.add_parser('validator', help='Validator command')

	args = parser.parse_args()

	cur_dir = os.path.dirname(os.path.abspath(__file__))

	if args.command == 'wallet':
		the_wallet = wallet.GetWallet()
		LogMsg("DSC v1.0")
		if args.wallet_command == 'create':
			the_wallet.CreateWallet()
		elif args.wallet_command == 'key':
			the_wallet.ShowKey()
		elif args.wallet_command == 'balance':
			the_wallet.GetBalance()
		elif args.wallet_command == 'send':
			the_wallet.CmdSendTransaction(args.amount, args.address)
		elif args.wallet_command == 'transaction':
			the_wallet.CmdQueryTransactionState(args.transaction_id)
		elif args.wallet_command == 'transactions':
			the_wallet.CmdQueryAllTransactions()
		elif args.wallet_command == 'throughput':
			the_wallet.CmdSendThroughputTest(args.num, args.address)
		else:
			print("unknown wallet command")
	elif args.command == 'pool':
		os.execv(os.path.join(cur_dir, "pool.py"), ["pool.py"])
	elif args.command == 'blockchain':
		os.execv(os.path.join(cur_dir, "blockchain.py"), ["blockchain.py"])
	elif args.command == 'validator':
		os.execv(os.path.join(cur_dir, "validator.py"), ["validator.py"])
	elif args.command == 'metronome':
		os.execv(os.path.join(cur_dir, "metronome.py"), ["metronome.py"])
	elif args.command == 'help':
		print("DSC: DataSys Coin Blockchain v1.0")
		print("run dsc.py -h for help")
	else:
		print("unknown command")
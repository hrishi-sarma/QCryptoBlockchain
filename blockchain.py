"""
Quantum-Secure Blockchain Implementation
Combines QKD for key distribution and PQC for signatures and encryption
"""

import json
import time
import hashlib
from typing import List, Dict, Optional
from datetime import datetime
from qkd_simulator import QKDSimulator
from pqc_crypto import NodeIdentity, PQCCrypto


class Transaction:
    """
    Represents a transaction in the blockchain.
    Signed with post-quantum Dilithium signatures (simulated with RSA).
    """
    
    def __init__(self, sender: str, receiver: str, amount: float, 
                 data: Optional[Dict] = None):
        """
        Create a new transaction.
        """
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.timestamp = time.time()
        self.data = data or {}
        self.signature: Optional[bytes] = None
        self.tx_hash: Optional[str] = None

        # NEW: Cache the exact bytes used for signing to guarantee verify matches
        self._signed_payload_bytes: Optional[bytes] = None
    
    def to_dict(self, include_signature: bool = True) -> Dict:
        """Convert transaction to dictionary"""
        tx_dict = {
            'sender': self.sender,
            'receiver': self.receiver,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'data': self.data
        }
        if include_signature and self.signature:
            tx_dict['signature'] = self.signature.hex()
        if self.tx_hash:
            tx_dict['tx_hash'] = self.tx_hash
        return tx_dict
    
    def to_bytes(self) -> bytes:
        """
        Convert transaction to bytes for signing (without signature).
        Deterministic JSON serialization (sorted keys + compact separators).
        """
        tx_dict = self.to_dict(include_signature=False)
        return json.dumps(tx_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    def calculate_hash(self) -> str:
        """Calculate hash of transaction including signature"""
        tx_dict = self.to_dict(include_signature=True)
        tx_string = json.dumps(tx_dict, sort_keys=True)
        return hashlib.sha256(tx_string.encode('utf-8')).hexdigest()
    
    def sign_transaction(self, node_identity: NodeIdentity):
        """
        Sign transaction using post-quantum signature (simulated).
        """
        if self.sender != node_identity.node_id:
            raise ValueError("Cannot sign transaction from different sender")
        
        tx_bytes = self.to_bytes()
        self._signed_payload_bytes = tx_bytes[:]  # cache exact bytes used for signing
        self.signature = node_identity.sign(tx_bytes)
        self.tx_hash = self.calculate_hash()
        print(f"[TX] Transaction signed by {self.sender}")
        # Debug (optional):
        # print(f"[DEBUG] Signed payload SHA256: {hashlib.sha256(self._signed_payload_bytes).hexdigest()}")
    
    def verify_signature(self, public_key: bytes) -> bool:
        """
        Verify transaction signature with the cached signed payload if available.
        """
        if not self.signature:
            return False
        
        # Prefer the exact bytes we signed originally; fall back to recompute
        tx_bytes = self._signed_payload_bytes if self._signed_payload_bytes is not None else self.to_bytes()
        pqc = PQCCrypto()
        ok = pqc.verify_signature(tx_bytes, self.signature, public_key)
        # Debug (optional):
        # print(f"[DEBUG] Verify payload SHA256: {hashlib.sha256(tx_bytes).hexdigest()}  ok={ok}")
        return ok


class Block:
    """
    Represents a block in the blockchain.
    Contains multiple transactions and is linked to previous block.
    """
    
    def __init__(self, index: int, transactions: List[Transaction], 
                 previous_hash: str, qkd_metadata: Optional[Dict] = None):
        """
        Create a new block.
        """
        self.index = index
        self.transactions = transactions
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.qkd_metadata = qkd_metadata or {}
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """
        Calculate hash of the block.
        Includes all transactions, previous hash, and QKD metadata for traceability.
        """
        block_data = {
            'index': self.index,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'qkd_metadata': self.qkd_metadata,
            'nonce': self.nonce
        }
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()
    
    def mine_block(self, difficulty: int = 2):
        """
        Mine block with proof-of-work (simple implementation).
        """
        target = '0' * difficulty
        print(f"[MINING] Mining block {self.index}...")
        
        start_time = time.time()
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        elapsed = time.time() - start_time
        print(f"[MINING] Block {self.index} mined! Hash: {self.hash[:16]}... (took {elapsed:.2f}s, nonce: {self.nonce})")
    
    def to_dict(self) -> Dict:
        """Convert block to dictionary for serialization"""
        return {
            'index': self.index,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'qkd_metadata': self.qkd_metadata,
            'nonce': self.nonce,
            'hash': self.hash
        }


class QuantumBlockchain:
    """
    Blockchain with quantum-secure features:
    - QKD for secure key distribution between nodes
    - Post-quantum cryptography (Dilithium) for transaction signatures
    - Traceability through QKD metadata in blocks
    """
    
    def __init__(self, difficulty: int = 2):
        """
        Initialize blockchain.
        """
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.difficulty = difficulty
        self.qkd = QKDSimulator(key_length=256)
        self.nodes: Dict[str, NodeIdentity] = {}
        
        # Create genesis block
        self._create_genesis_block()
        
        print(f"[BLOCKCHAIN] Initialized with difficulty {difficulty}")
    
    def _create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = Block(0, [], "0", {"genesis": True})
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
        print("[BLOCKCHAIN] Genesis block created")
    
    def register_node(self, node_id: str) -> NodeIdentity:
        """
        Register a new node in the network.
        """
        if node_id in self.nodes:
            print(f"[BLOCKCHAIN] Node {node_id} already registered")
            return self.nodes[node_id]
        
        node_identity = NodeIdentity(node_id)
        self.nodes[node_id] = node_identity
        print(f"[BLOCKCHAIN] Node {node_id} registered")
        return node_identity
    
    def establish_qkd_channel(self, node_a: str, node_b: str) -> Dict:
        """
        Establish QKD channel between two nodes.
        Simulates quantum key distribution for secure communication.
        """
        print(f"\n[QKD] Establishing quantum channel between {node_a} and {node_b}")
        
        key_a, key_b, metadata = self.qkd.generate_key_pair()
        if key_a != key_b:
            raise Exception("QKD failed: Keys don't match!")
        
        qkd_info = {
            'node_a': node_a,
            'node_b': node_b,
            'key_hash': hashlib.sha256(key_a).hexdigest(),
            'timestamp': time.time(),
            'protocol': metadata['protocol'],
            'error_rate': metadata['error_rate'],
            'is_secure': metadata['is_secure']
        }
        
        print(f"[QKD] Channel established successfully")
        print(f"[QKD] Shared key hash: {qkd_info['key_hash'][:32]}...")
        return qkd_info
    
    def create_transaction(self, sender: str, receiver: str, amount: float, 
                          data: Optional[Dict] = None) -> Transaction:
        """
        Create and sign a new transaction.
        """
        if sender not in self.nodes:
            raise ValueError(f"Sender {sender} not registered")
        if receiver not in self.nodes:
            raise ValueError(f"Receiver {receiver} not registered")
        
        transaction = Transaction(sender, receiver, amount, data)
        sender_identity = self.nodes[sender]
        transaction.sign_transaction(sender_identity)
        
        self.pending_transactions.append(transaction)
        print(f"[TX] Transaction created: {sender} -> {receiver} ({amount})")
        return transaction
    
    def mine_pending_transactions(self, miner_node: str):
        """Mine a new block with pending transactions."""
        if not self.pending_transactions:
            print("[MINING] No transactions to mine")
            return
        
        print(f"[MINING] Verifying {len(self.pending_transactions)} transaction signatures...")
        for tx in self.pending_transactions:
            if tx.sender not in self.nodes:
                raise ValueError(f"Sender {tx.sender} not found in registered nodes")
            sender_public_key = self.nodes[tx.sender].sign_public_key
            if not tx.verify_signature(sender_public_key):
                # Helpful context when debugging:
                try:
                    dbg_hash = hashlib.sha256((tx._signed_payload_bytes or tx.to_bytes())).hexdigest()
                except Exception:
                    dbg_hash = "N/A"
                raise ValueError(f"Invalid signature for transaction {tx.tx_hash} (payload_sha256={dbg_hash})")
        
        print("[MINING] All signatures verified successfully")
        qkd_metadata = self.establish_qkd_channel(miner_node, "network")
        
        previous_hash = self.chain[-1].hash
        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions,
            previous_hash=previous_hash,
            qkd_metadata=qkd_metadata
        )
        
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        self.pending_transactions = []
        print(f"[BLOCKCHAIN] Block {new_block.index} added to chain")
    
    def validate_chain(self) -> bool:
        """Validate entire blockchain integrity."""
        print("\n[VALIDATION] Validating blockchain...")
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if current_block.previous_hash != previous_block.hash:
                print(f"[VALIDATION] Block {i}: Previous hash mismatch")
                return False
            
            if current_block.hash != current_block.calculate_hash():
                print(f"[VALIDATION] Block {i}: Hash is invalid")
                return False
            
            for tx in current_block.transactions:
                if tx.sender not in self.nodes:
                    print(f"[VALIDATION] Block {i}: Sender {tx.sender} not found")
                    return False
                sender_public_key = self.nodes[tx.sender].sign_public_key
                if not tx.verify_signature(sender_public_key):
                    print(f"[VALIDATION] Block {i}: Invalid transaction signature from {tx.sender}")
                    return False
        
        print("[VALIDATION] Blockchain is valid!")
        return True
    
    def get_chain_info(self) -> Dict:
        """Get blockchain summary info."""
        return {
            'length': len(self.chain),
            'difficulty': self.difficulty,
            'nodes': list(self.nodes.keys()),
            'pending_transactions': len(self.pending_transactions),
            'blocks': [block.to_dict() for block in self.chain]
        }
    
    def trace_transaction(self, tx_hash: str) -> Optional[Dict]:
        """Trace a transaction through the blockchain."""
        for block in self.chain:
            for tx in block.transactions:
                if tx.tx_hash == tx_hash:
                    return {
                        'transaction': tx.to_dict(),
                        'block_index': block.index,
                        'block_hash': block.hash,
                        'block_timestamp': block.timestamp,
                        'qkd_metadata': block.qkd_metadata,
                        'confirmations': len(self.chain) - block.index
                    }
        return None
    
    def print_chain(self):
        """Print blockchain in human-readable form."""
        print("\n" + "="*80)
        print("QUANTUM-SECURE BLOCKCHAIN")
        print("="*80)
        for block in self.chain:
            print(f"\nBlock #{block.index}")
            print(f"Timestamp: {datetime.fromtimestamp(block.timestamp)}")
            print(f"Previous Hash: {block.previous_hash[:16]}...")
            print(f"Hash: {block.hash[:16]}...")
            print(f"Nonce: {block.nonce}")
            if block.qkd_metadata:
                print("QKD Metadata:")
                if 'key_hash' in block.qkd_metadata:
                    print(f"  - Key Hash: {block.qkd_metadata['key_hash'][:32]}...")
                if 'error_rate' in block.qkd_metadata:
                    print(f"  - Error Rate: {block.qkd_metadata['error_rate']:.4f}")
            print(f"Transactions ({len(block.transactions)}):")
            for tx in block.transactions:
                print(f"  {tx.sender} -> {tx.receiver}: {tx.amount}")
                if tx.data:
                    print(f"    Data: {tx.data}")
            print("-" * 80)

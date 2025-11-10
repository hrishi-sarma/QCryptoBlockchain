"""
Main Demo: Quantum-Secure Blockchain
Demonstrates the complete system with QKD, PQC, and blockchain
"""

from blockchain import QuantumBlockchain
import json
import time


def run_demo():
    """Run complete demonstration of quantum-secure blockchain"""
    
    print("\n" + "="*80)
    print("QUANTUM-SECURE BLOCKCHAIN DEMONSTRATION")
    print("="*80)
    print("\nThis demo showcases:")
    print("1. QKD (Quantum Key Distribution) using BB84 protocol")
    print("2. Post-Quantum Cryptography (Dilithium signatures, Kyber encryption)")
    print("3. Blockchain with quantum-secure features")
    print("4. Transaction traceability and verification")
    print("="*80 + "\n")
    
    time.sleep(2)
    
    # Initialize blockchain
    print("\n[STEP 1] Initializing Quantum-Secure Blockchain")
    print("-" * 80)
    blockchain = QuantumBlockchain(difficulty=2)
    
    time.sleep(1)
    
    # Register nodes
    print("\n[STEP 2] Registering Network Nodes")
    print("-" * 80)
    alice = blockchain.register_node("Alice")
    bob = blockchain.register_node("Bob")
    charlie = blockchain.register_node("Charlie")
    
    print(f"\nRegistered nodes: {list(blockchain.nodes.keys())}")
    
    time.sleep(1)
    
    # Create transactions with traceability data
    print("\n[STEP 3] Creating Quantum-Signed Transactions")
    print("-" * 80)
    
    tx1 = blockchain.create_transaction(
        sender="Alice",
        receiver="Bob",
        amount=50.0,
        data={
            "description": "Payment for quantum computing services",
            "category": "services",
            "project_id": "QC-2025-001"
        }
    )
    
    time.sleep(0.5)
    
    tx2 = blockchain.create_transaction(
        sender="Bob",
        receiver="Charlie",
        amount=25.0,
        data={
            "description": "Research grant transfer",
            "category": "research",
            "project_id": "QC-2025-002"
        }
    )
    
    time.sleep(0.5)
    
    tx3 = blockchain.create_transaction(
        sender="Charlie",
        receiver="Alice",
        amount=10.0,
        data={
            "description": "Equipment lease payment",
            "category": "equipment",
            "project_id": "QC-2025-003"
        }
    )
    
    print(f"\nPending transactions: {len(blockchain.pending_transactions)}")
    
    time.sleep(1)
    
    # Mine block
    print("\n[STEP 4] Mining Block with QKD Channel Establishment")
    print("-" * 80)
    blockchain.mine_pending_transactions("Alice")
    
    time.sleep(1)
    
    # Create more transactions
    print("\n[STEP 5] Creating Additional Transactions")
    print("-" * 80)
    
    tx4 = blockchain.create_transaction(
        sender="Alice",
        receiver="Charlie",
        amount=15.0,
        data={
            "description": "Consultancy fee",
            "category": "services",
            "project_id": "QC-2025-004"
        }
    )
    
    time.sleep(0.5)
    
    tx5 = blockchain.create_transaction(
        sender="Bob",
        receiver="Alice",
        amount=30.0,
        data={
            "description": "Quantum algorithm licensing",
            "category": "licensing",
            "project_id": "QC-2025-005"
        }
    )
    
    time.sleep(1)
    
    # Mine second block
    print("\n[STEP 6] Mining Second Block")
    print("-" * 80)
    blockchain.mine_pending_transactions("Bob")
    
    time.sleep(1)
    
    # Validate blockchain
    print("\n[STEP 7] Validating Blockchain")
    print("-" * 80)
    is_valid = blockchain.validate_chain()
    
    if is_valid:
        print("\nValidation Result: VALID")
        print("All blocks, transactions, and signatures verified successfully!")
    else:
        print("\nValidation Result: INVALID")
        print("Blockchain integrity compromised!")
    
    time.sleep(1)
    
    # Print blockchain
    blockchain.print_chain()
    
    time.sleep(1)
    
    # Demonstrate transaction tracing
    print("\n[STEP 8] Demonstrating Transaction Traceability")
    print("-" * 80)
    
    if blockchain.chain[1].transactions:
        traced_tx = blockchain.chain[1].transactions[0]
        trace_info = blockchain.trace_transaction(traced_tx.tx_hash)
        
        if trace_info:
            print(f"\nTracing transaction: {traced_tx.tx_hash[:32]}...")
            print(f"\nTransaction Details:")
            print(f"  Sender: {trace_info['transaction']['sender']}")
            print(f"  Receiver: {trace_info['transaction']['receiver']}")
            print(f"  Amount: {trace_info['transaction']['amount']}")
            print(f"  Description: {trace_info['transaction']['data'].get('description', 'N/A')}")
            print(f"  Category: {trace_info['transaction']['data'].get('category', 'N/A')}")
            print(f"  Project ID: {trace_info['transaction']['data'].get('project_id', 'N/A')}")
            
            print(f"\nBlock Information:")
            print(f"  Block Index: {trace_info['block_index']}")
            print(f"  Block Hash: {trace_info['block_hash'][:32]}...")
            print(f"  Confirmations: {trace_info['confirmations']}")
            
            print(f"\nQKD Security Metadata:")
            qkd_meta = trace_info['qkd_metadata']
            print(f"  Protocol: {qkd_meta.get('protocol', 'N/A')}")
            print(f"  Key Hash: {qkd_meta.get('key_hash', 'N/A')[:32]}...")
            print(f"  Error Rate: {qkd_meta.get('error_rate', 0):.4%}")
            print(f"  Security Status: {'SECURE' if qkd_meta.get('is_secure') else 'INSECURE'}")
    
    time.sleep(1)
    
    # Summary
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)
    print("\nSummary of Quantum Security Features:")
    print("\n1. QKD (Quantum Key Distribution):")
    print("   - BB84 protocol simulated for each block")
    print("   - Generates shared secret keys between nodes")
    print("   - Detects eavesdropping through error rate monitoring")
    print("   - Key metadata stored in blocks for auditability")
    
    print("\n2. Post-Quantum Cryptography:")
    print("   - Crystals-Dilithium for digital signatures")
    print("   - Quantum-resistant transaction signing")
    print("   - Secure against both classical and quantum attacks")
    print("   - Crystals-Kyber ready for encryption (demonstrated in pqc_crypto.py)")
    
    print("\n3. Blockchain Features:")
    print("   - Immutable transaction ledger")
    print("   - Complete transaction traceability")
    print("   - Proof-of-work consensus")
    print("   - Comprehensive validation of chain integrity")
    
    print("\n4. Security Properties:")
    print("   - Confidentiality: QKD ensures secure key exchange")
    print("   - Integrity: Blockchain hashing prevents tampering")
    print("   - Authentication: PQC signatures verify identities")
    print("   - Non-repudiation: Signed transactions cannot be denied")
    print("   - Traceability: Full audit trail with QKD metadata")
    
    print("\n" + "="*80)
    
    # Export blockchain data
    print("\n[OPTIONAL] Exporting blockchain data...")
    chain_info = blockchain.get_chain_info()
    
    with open('blockchain_export.json', 'w') as f:
        json.dump(chain_info, f, indent=2, default=str)
    
    print("Blockchain data exported to: blockchain_export.json")
    print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    run_demo()
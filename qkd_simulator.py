"""
QKD (Quantum Key Distribution) Simulator using BB84 Protocol
This simulates the quantum key exchange process between two parties (Alice and Bob)
"""

import random
import hashlib
from typing import Tuple, List

class QKDSimulator:
    """
    Simulates BB84 Quantum Key Distribution protocol.
    
    BB84 Protocol Steps:
    1. Alice generates random bits and random bases
    2. Alice sends qubits to Bob encoded in her chosen bases
    3. Bob measures qubits using randomly chosen bases
    4. Alice and Bob compare bases publicly (not the bits)
    5. They keep only bits where bases matched
    6. They verify security by checking a sample of bits for eavesdropping
    """
    
    def __init__(self, key_length: int = 256, error_threshold: float = 0.11):
        """
        Initialize QKD simulator.
        
        Args:
            key_length: Desired length of the final key in bits
            error_threshold: Maximum acceptable error rate (QBER - Quantum Bit Error Rate)
        """
        self.key_length = key_length
        self.error_threshold = error_threshold
        # We need to generate more bits initially since only ~50% will have matching bases
        self.initial_bits = key_length * 4
        
    def generate_random_bits(self, n: int) -> List[int]:
        """Generate n random bits (0 or 1)"""
        return [random.randint(0, 1) for _ in range(n)]
    
    def generate_random_bases(self, n: int) -> List[str]:
        """
        Generate n random bases for encoding/measuring qubits.
        
        Two bases are used in BB84:
        - 'rectilinear' (+): horizontal/vertical polarization (0 = H, 1 = V)
        - 'diagonal' (x): diagonal polarization (0 = +45°, 1 = -45°)
        """
        return [random.choice(['rectilinear', 'diagonal']) for _ in range(n)]
    
    def encode_qubits(self, bits: List[int], bases: List[str]) -> List[Tuple[int, str]]:
        """
        Alice encodes her bits into qubits using her chosen bases.
        Returns list of (bit, basis) tuples representing the quantum state.
        """
        return list(zip(bits, bases))
    
    def measure_qubits(self, qubits: List[Tuple[int, str]], measurement_bases: List[str]) -> List[int]:
        """
        Bob measures the qubits using his randomly chosen bases.
        
        If Bob's basis matches Alice's basis: measurement is correct
        If Bob's basis differs: measurement result is random (50% error)
        """
        measured_bits = []
        for (bit, encoding_basis), measurement_basis in zip(qubits, measurement_bases):
            if encoding_basis == measurement_basis:
                # Bases match - measurement is correct
                measured_bits.append(bit)
            else:
                # Bases don't match - measurement is random
                measured_bits.append(random.randint(0, 1))
        return measured_bits
    
    def sift_key(self, alice_bits: List[int], alice_bases: List[str], 
                 bob_bits: List[int], bob_bases: List[str]) -> Tuple[List[int], List[int]]:
        """
        Sifting process: Alice and Bob compare their bases publicly.
        They keep only the bits where their bases matched.
        
        Returns: (alice_sifted_key, bob_sifted_key)
        """
        alice_sifted = []
        bob_sifted = []
        
        for a_bit, a_basis, b_bit, b_basis in zip(alice_bits, alice_bases, bob_bits, bob_bases):
            if a_basis == b_basis:
                alice_sifted.append(a_bit)
                bob_sifted.append(b_bit)
        
        return alice_sifted, bob_sifted
    
    def check_eavesdropping(self, alice_key: List[int], bob_key: List[int], 
                           sample_size: int = 50) -> Tuple[bool, float]:
        """
        Check for eavesdropping by comparing a random sample of bits.
        
        In real QKD, any eavesdropper (Eve) trying to intercept and measure
        the qubits will introduce errors due to the no-cloning theorem.
        
        Returns: (is_secure, error_rate)
        """
        if len(alice_key) < sample_size:
            sample_size = len(alice_key) // 2
        
        # Randomly select positions to check
        sample_positions = random.sample(range(len(alice_key)), sample_size)
        
        errors = 0
        for pos in sample_positions:
            if alice_key[pos] != bob_key[pos]:
                errors += 1
        
        error_rate = errors / sample_size
        is_secure = error_rate <= self.error_threshold
        
        # Remove the checked bits from the key (they've been revealed publicly)
        alice_key = [bit for i, bit in enumerate(alice_key) if i not in sample_positions]
        bob_key = [bit for i, bit in enumerate(bob_key) if i not in sample_positions]
        
        return is_secure, error_rate, alice_key, bob_key
    
    def generate_key_pair(self) -> Tuple[bytes, bytes, dict]:
        """
        Execute complete QKD protocol to generate shared secret key.
        
        Returns: (alice_key, bob_key, metadata)
        """
        print(f"[QKD] Starting BB84 protocol for {self.key_length}-bit key generation...")
        
        # Step 1: Alice generates random bits and bases
        alice_bits = self.generate_random_bits(self.initial_bits)
        alice_bases = self.generate_random_bases(self.initial_bits)
        print(f"[QKD] Alice prepared {self.initial_bits} qubits")
        
        # Step 2: Alice encodes and sends qubits
        qubits = self.encode_qubits(alice_bits, alice_bases)
        
        # Step 3: Bob generates random bases and measures
        bob_bases = self.generate_random_bases(self.initial_bits)
        bob_bits = self.measure_qubits(qubits, bob_bases)
        print(f"[QKD] Bob measured {self.initial_bits} qubits")
        
        # Step 4: Sifting - keep only matching bases
        alice_sifted, bob_sifted = self.sift_key(alice_bits, alice_bases, bob_bits, bob_bases)
        print(f"[QKD] After sifting: {len(alice_sifted)} bits remain (bases matched)")
        
        # Step 5: Check for eavesdropping
        is_secure, error_rate, alice_final, bob_final = self.check_eavesdropping(
            alice_sifted, bob_sifted
        )
        
        if not is_secure:
            raise Exception(f"QKD FAILED: High error rate detected ({error_rate:.2%}). Possible eavesdropping!")
        
        print(f"[QKD] Security check passed. Error rate: {error_rate:.2%}")
        
        # Truncate to desired key length
        alice_final = alice_final[:self.key_length]
        bob_final = bob_final[:self.key_length]
        
        # Convert bit lists to bytes
        alice_key = bytes(int(''.join(map(str, alice_final[i:i+8])), 2) 
                         for i in range(0, len(alice_final), 8))
        bob_key = bytes(int(''.join(map(str, bob_final[i:i+8])), 2) 
                       for i in range(0, len(bob_final), 8))
        
        metadata = {
            'protocol': 'BB84',
            'initial_bits': self.initial_bits,
            'sifted_bits': len(alice_sifted),
            'final_key_length': len(alice_key) * 8,
            'error_rate': error_rate,
            'is_secure': is_secure
        }
        
        print(f"[QKD] Key generation successful! Final key: {len(alice_key)} bytes")
        
        return alice_key, bob_key, metadata


if __name__ == "__main__":
    # Demo
    qkd = QKDSimulator(key_length=256)
    alice_key, bob_key, metadata = qkd.generate_key_pair()
    
    print("\n--- QKD Result ---")
    print(f"Alice's key: {alice_key.hex()[:64]}...")
    print(f"Bob's key:   {bob_key.hex()[:64]}...")
    print(f"Keys match: {alice_key == bob_key}")
    print(f"\nMetadata: {metadata}")
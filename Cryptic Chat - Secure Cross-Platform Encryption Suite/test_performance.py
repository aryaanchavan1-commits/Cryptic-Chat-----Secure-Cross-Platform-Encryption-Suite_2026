import time
from cryptic import AES256

def test_encryption_speed():
    """Test encryption and decryption speed"""
    
    # Test different data sizes
    test_sizes = [100, 1000, 10000, 100000, 1000000]  # 100B, 1KB, 10KB, 100KB, 1MB
    
    print("=" * 60)
    print("Performance Test - AES-256-GCM Encryption/Decryption")
    print("=" * 60)
    print(f"{'Data Size':<15}{'Encryption (ms)':<20}{'Decryption (ms)':<20}{'Total (ms)':<15}")
    print("-" * 60)
    
    password = "StrongPassword123!@#"
    
    for size in test_sizes:
        # Create test data
        data = b"X" * size
        
        # Test encryption
        start_time = time.time()
        encrypted = AES256.encrypt(data, password)
        encrypt_time = (time.time() - start_time) * 1000
        
        # Test decryption
        start_time = time.time()
        decrypted = AES256.decrypt(encrypted, password)
        decrypt_time = (time.time() - start_time) * 1000
        
        # Verify decryption
        assert decrypted == data
        
        # Calculate throughput
        total_time = encrypt_time + decrypt_time
        
        size_str = f"{size} bytes"
        if size >= 1000:
            size_str = f"{size/1000:.1f} KB"
        if size >= 1000000:
            size_str = f"{size/1000000:.1f} MB"
        
        print(f"{size_str:<15}{encrypt_time:<20.2f}{decrypt_time:<20.2f}{total_time:<15.2f}")
    
    print("\nPerformance test completed successfully!")
    print("Note: Encryption includes PBKDF2 key derivation (300,000 iterations)")

def test_password_strength():
    """Test password strength assessment"""
    from cryptic import PasswordStrength
    
    test_passwords = [
        "password",
        "123456",
        "Password123",
        "StrongPassword123!",
        "S@ltedP@ssw0rd!2026",
        "A" * 12,
        "aB3!@#$%^&*()_+=-"
    ]
    
    print("\n" + "=" * 60)
    print("Password Strength Assessment")
    print("=" * 60)
    print(f"{'Password':<30}{'Score (0-5)':<15}{'Strength Level'}")
    print("-" * 60)
    
    for password in test_passwords:
        score = PasswordStrength.score(password)
        if score == 0:
            strength = "Very Weak"
        elif score == 1:
            strength = "Weak"
        elif score == 2:
            strength = "Fair"
        elif score == 3:
            strength = "Good"
        elif score == 4:
            strength = "Strong"
        else:
            strength = "Excellent"
        
        print(f"{password:<30}{score:<15}{strength}")

if __name__ == "__main__":
    try:
        test_encryption_speed()
        test_password_strength()
    except Exception as e:
        print(f"\nError during test: {e}")

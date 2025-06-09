#!/usr/bin/env python3
"""Basic test for XOR decoding functionality without Binary Ninja dependencies"""

def read_xored_data(filename):
    """Read XOR-encoded data from file"""
    with open(filename, 'rb') as fr:
        data = fr.read()
    # XOR each byte with 0x69
    result = bytes(b ^ 0x69 for b in data)
    return result

def test_xor_decoding():
    """Test XOR decoding with demo files"""
    try:
        rnam_data = read_xored_data('DOTTDEMO.000')  # RNAM file
        lecf_data = read_xored_data('DOTTDEMO.001')  # LECF file
        
        assert lecf_data[:4] == b'LECF', f'Expected LECF, got {lecf_data[:4]}'
        assert rnam_data[:4] == b'RNAM', f'Expected RNAM, got {rnam_data[:4]}'
        
        print('✅ XOR decoding test passed')
        return True
    except FileNotFoundError:
        print('⚠️ Demo files not found, skipping XOR test')
        return True
    except Exception as e:
        print(f'❌ XOR decoding test failed: {e}')
        return False

if __name__ == '__main__':
    success = test_xor_decoding()
    exit(0 if success else 1)

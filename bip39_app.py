import streamlit as st
import hashlib
import hmac
import secrets
from typing import List, Tuple
import requests


## Getting the wordlist from BIP-39 (English)

# URL of the raw text file on GitHub
url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"

# Fetch the file content
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Print the content of the file
    word_list = response.text.split()
    #print(file_content)
else:
    print(f"Failed to retrieve the file. Status code: {response.status_code}")


import streamlit as st
import hashlib
import hmac
import secrets
from typing import List, Tuple

class BIP39:
    def __init__(self):
        # Load the complete BIP-39 English wordlist
        self.word_list = word_list
        self.word_map = {word: index for index, word in enumerate(self.word_list)}

    def generate_entropy(self, bits: int = 128) -> bytes:
        if bits not in (128, 256):
            raise ValueError("Bits must be either 128 or 256")
        return secrets.token_bytes(bits // 8)

    def calculate_checksum(self, entropy: bytes) -> str:
        """Calculate checksum bits for the entropy"""
        ent_length = len(entropy) * 8
        checksum_length = ent_length // 32
        
        # Calculate SHA256 hash
        hash_bytes = hashlib.sha256(entropy).digest()
        # Convert to binary string and take required number of bits
        hash_bits = bin(int.from_bytes(hash_bytes, byteorder='big'))[2:].zfill(256)
        return hash_bits[:checksum_length]

    def generate_mnemonic(self, entropy_bits: int = 128) -> List[str]:
        """Generate mnemonic phrase from random entropy"""
        entropy = self.generate_entropy(entropy_bits)
        
        # Convert entropy to binary string
        entropy_bits = bin(int.from_bytes(entropy, byteorder='big'))[2:].zfill(len(entropy) * 8)
        
        # Calculate and append checksum
        checksum = self.calculate_checksum(entropy)
        combined_bits = entropy_bits + checksum
        
        # Split into 11-bit chunks and convert to words
        words = []
        for i in range(0, len(combined_bits), 11):
            chunk = combined_bits[i:i+11]
            index = int(chunk, 2)
            words.append(self.word_list[index])
        
        return words

    def calculate_last_word(self, initial_words: List[str]) -> List[str]:
        """Calculate possible last words given the initial words"""
        if len(initial_words) not in (11, 23):
            raise ValueError("Must provide either 11 or 23 words")
        
        # Convert initial words to binary string
        binary = ''
        for word in initial_words:
            if word not in self.word_map:
                raise ValueError(f"Invalid word: {word}")
            index = self.word_map[word]
            binary += format(index, '011b')
        
        # Calculate entropy length and checksum length
        entropy_bits = 128 if len(initial_words) == 11 else 256
        checksum_bits = entropy_bits // 32
        
        possible_words = []
        # Try all possible last words
        for i in range(2048):
            test_binary = binary + format(i, '011b')
            
            # Extract entropy portion
            test_entropy = int(test_binary[:entropy_bits], 2).to_bytes(entropy_bits // 8, byteorder='big')
            
            # Calculate checksum for this combination
            test_checksum = self.calculate_checksum(test_entropy)
            
            # Compare with the checksum bits in our test binary
            if test_binary[entropy_bits:] == test_checksum:
                possible_words.append(self.word_list[i])
        
        return possible_words

def main():
    st.title("BIP-39 Mnemonic Explorer")
    
    # Introduction
    st.markdown("""
    ## We are trying to understand how BIP-39 mnemonics generations works
    
    While discussing how bitcoin wallets generate the seed keys, https://x.com/LVNilesh gave me a small pet project 
    to try to do the mnemonic generation process myself and figure out how the validation of the last word happens. 
    This app does the same. You can access the python code in the repo here: 
                
    BIP-39 (Bitcoin Improvement Proposal 39) is a standard that converts random numbers into 
    memorable phrases. These phrases can be used to generate cryptocurrency wallets and are easier 
    to back up and remember than raw private keys.
    
    ### How it Works:
    1. Generate random entropy (128 or 256 bits)
    2. Add a checksum
    3. Convert to 12 or 24 memorable words
    """)

    st.divider()
    
    # Generate New Mnemonic Section
    st.header("📝 Generate New Mnemonic")
    st.markdown("""
    Choose between:
    - **12 words** (128 bits of entropy + 4 bits checksum)
    - **24 words** (256 bits of entropy + 8 bits checksum)
    
    A longer phrase provides more security but might be harder to remember.
    """)
    
    entropy_bits = st.radio("Select entropy bits:", [128, 256], 
                          format_func=lambda x: f"{x} bits ({x//32 + 3} words)")
    
    if st.button("Generate New Mnemonic"):
        bip39 = BIP39()
        mnemonic = bip39.generate_mnemonic(entropy_bits)
        st.session_state['mnemonic'] = mnemonic
        st.session_state['mnemonic_string'] = " ".join(mnemonic)
    
    if 'mnemonic' in st.session_state:
        st.info("Your generated mnemonic phrase:")
        st.text_area("Copy or write down these words in order:", 
                    st.session_state['mnemonic_string'], 
                    height=100)
        
        st.warning("""
        🔒 **Security Tips:**
        - Never share your mnemonic phrase
        - Store it securely offline
        - Write it down physically
        - Verify each word carefully
        - If you are storing these on a device that can connect to internet you are NGMI.
        - Being paranoid about keys is healthy
        """)
    
    st.divider()
    
    # Last Word Calculator Section
    st.header("🔍 Last Word Calculator")
    st.markdown("""
    This tool demonstrates how BIP-39's checksum works. Given the first 11 (or 23) words 
    of a mnemonic, it can calculate what the last word should be.
    
    ### How it Works:
    1. Takes the first 11/23 words
    2. Converts them to binary
    3. Calculates valid checksums
    4. Finds word(s) that satisfy the checksum
    
    This is useful for:
    - Recovering damaged mnemonics
    - Understanding BIP-39 validation
    - Learning about cryptocurrency security
    """)
    
    initial_words = st.text_area("Enter first 11 or 23 words (space-separated):",
                                help="Paste the first 11 (or 23) words of your mnemonic here")
    
    if st.button("Calculate Possible Last Words"):
        try:
            bip39 = BIP39()
            words = initial_words.strip().split()
            if len(words) not in (11, 23):
                st.error("Please enter either 11 or 23 words")
            else:
                possible_words = bip39.calculate_last_word(words)
                if possible_words:
                    st.success(f"Found {len(possible_words)} possible last words:")
                    st.write(", ".join(possible_words))
                    
                    if len(possible_words) == 1:
                        st.info("✅ This is the correct last word for your mnemonic!")
                    else:
                        st.info("Multiple possibilities found. Additional verification needed.")
                else:
                    st.error("No valid last words found. Please check the input words.")
        except ValueError as e:
            st.error(str(e))
    
    # Educational Footer
    st.divider()
    st.markdown("""
    ### 📚 Learn More
    
    - BIP-39 is used by most modern cryptocurrency wallets
    - The checksum ensures typing mistakes can be detected
    - Each word comes from a list of 2048 possible words
    - The entire system is deterministic and standardized
    
      ### Key Features:
    - **Standardized**: Works across different wallets and cryptocurrencies
    - **Secure**: Uses cryptographic randomness
    - **Error-checking**: Built-in checksum verification
    - **Memorable**: Uses common English words
                
    ⚠️ **Important**: This is an educational tool. Never enter real mnemonic phrases used 
    for actual cryptocurrency wallets on any website.
    
       ### 🔗 **Resources**:
    - [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
    - [Bitcoin Wiki - Seed phrase](https://en.bitcoin.it/wiki/Seed_phrase)
    - https://learnmeabitcoin.com/technical/keys/hd-wallets/mnemonic-seed/
    - https://medium.com/thecapital/cryptocurrency-911-how-does-12-word-seed-phrase-work-9d892de9732
    - I used claude for code generation purposes
                 """)
    

if __name__ == "__main__":
    st.set_page_config(
        page_title="BIP-39 Explorer",
        page_icon="🔑",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    main()
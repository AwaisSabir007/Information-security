from typing import Tuple, Union
from PIL import Image
import io

def str_to_bin(message: str) -> str:
    """Convert string to binary string."""
    return ''.join(format(ord(c), '08b') for c in message)

def bin_to_str(binary: str) -> str:
    """Convert binary string to text."""
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

def encode_image(image_path: Union[str,  io.BytesIO], message: str) -> Image.Image:
    """
    Hide a message inside an image using LSB (Least Significant Bit) Steganography.
    Adds a '####' delimiter to mark the end of the message.
    """
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    encoded = img.copy()
    width, height = img.size
    
    # Append delimiter to know when to stop decoding
    message += "####"
    binary_message = str_to_bin(message)
    data_len = len(binary_message)
    
    # Check if image is big enough
    if data_len > width * height * 3:
        raise ValueError(f"Message too long for this image. Max bits: {width * height * 3}, Needed: {data_len}")
    
    data_index = 0
    pixels = encoded.load()
    
    for y in range(height):
        for x in range(width):
            if data_index < data_len:
                r, g, b = pixels[x, y]
                
                # Modify LSB of Red
                if data_index < data_len:
                    r = (r & ~1) | int(binary_message[data_index])
                    data_index += 1
                    
                # Modify LSB of Green
                if data_index < data_len:
                    g = (g & ~1) | int(binary_message[data_index])
                    data_index += 1
                    
                # Modify LSB of Blue
                if data_index < data_len:
                    b = (b & ~1) | int(binary_message[data_index])
                    data_index += 1
                
                pixels[x, y] = (r, g, b)
            else:
                break
        if data_index >= data_len:
            break
            
    return encoded

def decode_image(image_file: Union[str, io.BytesIO]) -> str:
    """
    Extract a hidden message from an image. 
    Stops when '####' delimiter is found.
    """
    img = Image.open(image_file)
    if img.mode != 'RGB':
        img = img.convert('RGB')
        
    binary_data = ""
    pixels = img.load()
    width, height = img.size
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
            
    # Try to find delimiter
    current_chars = ""
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) < 8:
            break
        char = chr(int(byte, 2))
        current_chars += char
        
        if current_chars.endswith("####"):
            return current_chars[:-4]  # Return message without delimiter
            
    return "[No hidden message found or image corrupted]"

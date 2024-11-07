from PIL import Image
import sys
import time
from termcolor import colored

# Function to embed a message in an image
def hide_message_in_image(image_path, message, output_path):
    image = Image.open(image_path).convert("RGB")  # Ensure image is in RGB mode
    encoded_image = image.copy()
    width, height = image.size

    # Append a delimiter to the message to signify end of message
    message += "ENDMSG"
    message_binary = ''.join(format(ord(char), '08b') for char in message)
    message_len = len(message_binary)
    data_index = 0

    for y in range(height):
        for x in range(width):
            if data_index < message_len:
                pixel = list(image.getpixel((x, y)))
                for i in range(3):
                    if data_index < message_len:
                        pixel[i] = pixel[i] & 254 | int(message_binary[data_index])
                        data_index += 1
                encoded_image.putpixel((x, y), tuple(pixel))
            else:
                break
        if data_index >= message_len:
            break

    encoded_image.save(output_path)

# Function to retrieve a hidden message from an image
def retrieve_message_from_image(image_path):
    image = Image.open(image_path).convert("RGB")  # Ensure image is in RGB mode
    width, height = image.size

    binary_message = ""
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            for i in range(3):
                binary_message += str(pixel[i] & 1)

    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i + 8]
        char = chr(int(byte, 2))
        if message.endswith("ENDMSG"):
            break
        message += char

    return message[:-6]  # Remove the "ENDMSG" delimiter

# Function to print a delay message
def delay_print(string):
    for c in string:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(0.05)
    print()

# Fun ASCII art and welcome message
def welcome_message():
    print(colored("""  
   _____ __            
  / ___// /____  ____ _
  \__ \/ __/ _ \/ __ `/
 ___/ / /_/  __/ /_/ / 
/____/\__/\___/\__, /  
              /____/   
    """, "cyan"))
    delay_print(colored("Created By Winston Ighodaro!", "cyan"))
    delay_print(colored("Sometimes the most secure place for a message is where it's least expected-in plain sight, buried in the ordinary", "cyan"))

# Main function
def main():
    welcome_message()
    action = input(colored("Do you want to hide a message in an image or retrieve a message from an image? (hide/retrieve): ", "cyan")).strip().lower()

    if action not in ["hide", "retrieve"]:
        print(colored("Invalid action. Use 'hide' to hide a message or 'retrieve' to retrieve a message.", "red"))
        sys.exit(1)

    image_path = input(colored("Enter the image path: ", "cyan")).strip()
    
    if action == "hide":
        message = input(colored("Enter the message to hide: ", "cyan")).strip()

        output_image_path = input(colored("Enter the output image path (with extension, e.g., output.png): ", "cyan")).strip()
        hide_message_in_image(image_path, message, output_image_path)
        delay_print(colored(f"Mission accomplished! Your message has been hidden in {output_image_path}", "green"))
    elif action == "retrieve":
        message = retrieve_message_from_image(image_path)
        if message:
            delay_print(colored(f"Mission accomplished! Hidden message: {message}", "green"))
        else:
            print(colored("Failed to retrieve the message. Image may not contain a hidden message or could be corrupted.", "red"))

if __name__ == "__main__":
    main()


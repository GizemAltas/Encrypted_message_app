import socket
import rsa
import threading
from Crypto.Cipher import AES
import os

def receive_messages(client_socket, cipher):
    while True:
        try:
            # Veriyi al
            incoming_data = client_socket.recv(4096) 
            if not incoming_data:
                print("Bağlantı kapatıldı.")
                break

            # Nonce, şifreli veri ve tag'i ayır
            nonce = incoming_data[:16]
            tag = incoming_data[-16:]
            encrypted_data = incoming_data[16:-16]

            # Yeni bir Cipher nesnesi ile veriyi çöz
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

            # Eğer veri 'file:' ile başlıyorsa, dosya olarak işle
            if decrypted_data.startswith(b'file:'):
                file_name = decrypted_data[5:].decode('utf-8') #ilk 5 karakterden sonraki kısmı çıkarır
                with open(file_name, "wb") as file: # w:veri yazabilrsin b:ikilimod                   
                    file.write(decrypted_data)
                print(f"Dosya alındı ve kaydedildi: {file_name}")
            else:
                message = decrypted_data.decode('utf-8')
                print(f"Mesaj: {message}")

        except Exception as e:
            print(f"Hata: {e}")
            break


def send_messages(client_socket, cipher):
    while True:
        message = input("Mesaj: ")
        if message.lower() == 'q':#Döngü kullanıcı 'q' tuşuna basana kadar devam eder.
            client_socket.close()
            break
        elif message.startswith("sendfile"):
            _, file_path = message.split(maxsplit=1)
            send_file(client_socket, file_path)
        else:
            # Her mesaj için yeni bir Cipher nesnesi oluştur
            key = b"TheNeuralNineKey"  
            nonce = os.urandom(16)  # Her mesaj için yeni bir nonce
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            encrypted_message, tag = cipher.encrypt_and_digest(message.encode())
            
            # Nonce'u, şifreli mesajı ve tag'i gönder
            client_socket.send(nonce + encrypted_message + tag)

def send_file(client_socket, file_path):
    # Dosyanın varlığını kontrol et
    if not os.path.exists(file_path):
        print("File not found!")
        return

    # Dosyayı oku
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Her dosya için yeni bir Cipher nesnesi oluştur
    nonce = os.urandom(16)
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    encrypted_data, tag = cipher.encrypt_and_digest(file_data)

    # Dosya boyutunu ve şifrelenmiş veriyi gönder
    file_size = len(encrypted_data)
    header = f"file:{file_size}\n".encode()
    client_socket.sendall(header + nonce + encrypted_data + tag)
    
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9999))
# Sabit anahtar ve nonce
key = b"TheNeuralNineKey"
nonce = b"TheNeuarlNineNce"

# AES şifreleyiciyi oluştur
cipher = AES.new(key, AES.MODE_EAX, nonce)

# Mesaj alma ve gönderme için thread'ler
receive_thread = threading.Thread(target=receive_messages, args=(client, cipher))
send_thread = threading.Thread(target=send_messages, args=(client, cipher))

receive_thread.start()
send_thread.start()
receive_thread.join()
send_thread.join()
client.close()

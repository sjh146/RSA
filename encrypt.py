from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
def extract_aes_key(private_key_path):
    # 개인 키 로드
    with open(private_key_path, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())
    
    # RSA 복호화 객체 생성
    rsa_cipher = PKCS1_OAEP.new(private_key)
    
    # 암호화된 파일 열기
    with open(encrypted_file_path, 'rb') as enc_file:
        # 파일 구조: nonce(16바이트) + tag(16바이트) + 암호화된 AES 키 + 암호화된 데이터
        nonce = enc_file.read(16)
        tag = enc_file.read(16)
        
        # 암호화된 AES 키 읽기 (RSA-OAEP로 암호화된 AES 키의 길이는 256바이트)
        enc_aes_key = enc_file.read(256)
        
        # RSA로 암호화된 AES 키 복호화
        aes_key = rsa_cipher.decrypt(enc_aes_key)
        
        print(f"추출된 AES 키: {aes_key.hex()}")
        
        return aes_key, nonce, tag
def decrypt_file(encrypted_file_path, private_key_path, output_path=None):
    """
    암호화된 파일을 복호화하는 함수
    
    Args:
        encrypted_file_path (str): 암호화된 파일 경로
        private_key_path (str): RSA 개인 키 파일 경로
        output_path (str, optional): 복호화된 파일을 저장할 경로. 지정하지 않으면 원본 이름으로 저장
    
    Returns:
        str: 복호화된 파일 경로
    """
    # 출력 경로가 지정되지 않은 경우, 원본 파일 이름을 추측
    if output_path is None:
        # .enc 확장자 제거
        if encrypted_file_path.endswith('.enc'):
            output_path = encrypted_file_path[:-4]
        else:
            # 다른 이름으로 저장
            output_path = encrypted_file_path + '.decrypted'
    
    # 개인 키 로드
    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = RSA.import_key(key_file.read())
    except Exception as e:
        print(f"개인 키 로드 실패: {e}")
        return None
    
    # RSA 복호화 객체 생성
    rsa_cipher = PKCS1_OAEP.new(private_key)
    
    try:
        # 암호화된 파일 열기
        with open(encrypted_file_path, 'rb') as enc_file:
            # 파일 구조: nonce(16바이트) + tag(16바이트) + 암호화된 AES 키(256바이트) + 암호화된 데이터
            nonce = enc_file.read(16)
            tag = enc_file.read(16)
            
            # 암호화된 AES 키 읽기 (RSA-OAEP로 암호화된 AES 키의 길이는 256바이트)
            enc_aes_key = enc_file.read(256)
            
            # RSA로 암호화된 AES 키 복호화
            try:
                aes_key = rsa_cipher.decrypt(enc_aes_key)
                print(f"AES 키 복호화 성공: {aes_key.hex()}")
            except Exception as e:
                print(f"AES 키 복호화 실패: {e}")
                return None
            
            # 암호화된 데이터 읽기
            ciphertext = enc_file.read()
            
            # AES 복호화 객체 생성 (EAX 모드)
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            
            # 데이터 복호화
            try:
                data = cipher.decrypt_and_verify(ciphertext, tag)
                print("데이터 복호화 및 검증 성공")
            except Exception as e:
                print(f"데이터 복호화 또는 검증 실패: {e}")
                return None
            
            # 복호화된 데이터를 파일로 저장
            with open(output_path, 'wb') as f:
                f.write(data)
            
            print(f"파일 복호화 완료: {output_path}")
            return output_path
    
    except Exception as e:
        print(f"파일 복호화 중 오류 발생: {e}")
        return None

# 명령줄에서 실행할 때 사용할 수 있는 메인 함수
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='암호화된 파일 복호화')
    parser.add_argument('encrypted_file', help='복호화할 암호화된 파일 경로')
    parser.add_argument('private_key', help='RSA 개인 키 파일 경로')
    parser.add_argument('--output', '-o', help='복호화된 파일을 저장할 경로')
    
    args = parser.parse_args()
    
    decrypt_file(args.encrypted_file, args.private_key, args.output)

# 예제 사용법
if __name__ == "__main__":
    # 직접 실행 시 명령줄 인터페이스 활성화
    main()
    
    # 또는 아래 코드를 직접 수정하여 사용할 수 있습니다
    
    # 예제 코드:
    encrypted_file_path = 'E:/ss/user/red/Figure_2.png.enc'
    private_key_path = 'E:/ss/user/red/private.pem'
    output_path = 'E:/ss/user/red/복호화된_Figure_2.png'
    
    decrypt_file(encrypted_file_path, private_key_path, output_path)
    
# 사용 예시
# aes_key, nonce, tag = extract_aes_key('encrypted_file.enc', 'private.pem')
# print(f"추출된 AES 키: {aes_key.hex()}")
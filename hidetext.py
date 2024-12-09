#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Coded by: @charliecpln
# Github: @charliecpln
# Telegram: @charliecpln
# Discord: @charliecpln

# ANA KÜTÜPHANELER
import os
from sys import exit
import socket
import time
import base64
import hashlib
from hashlib import sha256

# EKRAN TEMİZLEME
def sil():
    try:
        name = os.name
        if name == "nt":
            os.system("cls")

        elif name == "posix":
            os.system("clear")
            
        else:
            print("[!] Desteklenmeyen işletim sistemi!")
            input("Devam etmek için enter'a basın...")
            exit(1)
    
    except Exception as e:
        print(f"[X] Hata: {e}")
        input("Devam etmek için enter'a basın...")

# İNTERNET BAĞLANTI TESTİ
def check_connection():
    print("[!] Bağlantı testi için '8.8.8.8' bağlantısı kurulmaya çalışılıyor...")
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        print("[+] Test başarılı.")
        return True
    except OSError:
        print("[!] Bağlantı testi başarısız oldu, bazı özellikler kullanılamayabilir!")
        input("Devam etmek için enter'a basın...")
        return False
    
# KÜTÜPHANE KONTROL
def check_libraries():
    try:
        print("\nKütüphaneler denetleniyor...\n")
        from colorama import Fore, Back, Style, init
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        import chardet
        from stegano import lsb

    except ImportError:
        oto_indirilsin_mi = input("\n[?] Eksik kütüphaneler bulundu, bunları otomatik olarak indirmek ister misiniz (y/n): ").lower().strip()
        if oto_indirilsin_mi.startswith("y"):
            setup()

        else:
            input("[!] Çıkmak için enter'a basın...")
            exit(1)

# KURULUM
def setup():
    try:
        print("[!] Kuruluma başlanıyor...")
        time.sleep(1)
        os.system("pip install colorama pycryptodome chardet pillow pystegano")
        sil()
        print("[+] Kurulum başarılı. Lütfen programı yeniden başlatın.")
        input("Devam etmek için enter'a basın...")
        exit(1)

    except Exception as e:
        print(f"[!] Hata: {e}")
        input("Devam etmek için enter'a basın...")
        exit(1)

# DENETİMLER
sil()
check_connection()
check_libraries()

# KÜTÜPHANELER 2
from colorama import Fore, Back, Style, init
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import chardet
from stegano import lsb

# COLORAMA AUTORESET
init(autoreset=True)

# BANNER
def banner():
    print(Style.BRIGHT + Fore.LIGHTRED_EX + r"""
        _____  ___  __   _____  ____  _______ 
  /\  /\\_   \/   \/__\ /__   \/__\ \/ /__   \
 / /_/ / / /\/ /\ /_\     / /\/_\  \  /  / /\/
/ __  /\/ /_/ /_///__    / / //__  /  \ / /   
\/ /_/\____/___,'\__/    \/  \__/ /_/\_\\/    
                                @charliecpln👻
""")
    print(Style.BRIGHT + Back.LIGHTRED_EX + Fore.LIGHTWHITE_EX + "[!] Bu kodun yönetici olarak çalıştırılması tavsiye edilir\n")

# DEVAM ETMEK İÇİN ENTER
def devam():
    input(Style.BRIGHT + Fore.LIGHTMAGENTA_EX + "\n[*] Devam etmek için 'enter' tuşuna basınız...\n")
    return main()

# İLETİŞİM
def contact():
    contact_menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
    [DISCORD]   -   @charliecpln
    [TELEGRAM]  -   @charliecpln
    [GİTHUB]    -   @charliecpln
    [THT]       -   @charliex2
"""
    print(contact_menu)
    devam()

# --------------- FONKSİYONLAR ---------------

# ANAHTAR ÜRETME
def generate_key():
    try:
        sabit = "hidetext"
        return hashlib.sha256(sabit.encode()).digest()
    
    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Genel hata: {e}")
        devam()

# AES ŞİFRELEME KEY
key = generate_key()
cipher = AES.new(key, AES.MODE_CBC)

# RESİM DOSYALARI İÇİN ŞİFRELEME KEYİ
key = b'Secure16ByteKey!'

# RESİM DOSYASI İÇİN ŞİFRELEME
def sifrele(mesaj):
    try:
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(mesaj.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
        
    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Şifreleme sırasında hata: {e}")
        return None

# RESİM DOSYASIN İÇİN ŞİFRE ÇMÖMZE
def sifre_coz(sifreli_mesaj):
    try:
        encrypted_data = base64.b64decode(sifreli_mesaj)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Şifre çözme sırasında hata: {e}")
        return None

# RESİM DOSYALARINA MESAJ GOMME
def mesaj_gomme(resim_yolu, mesaj, cikti_dosyasi):
    try:
        sifreli_mesaj = sifrele(mesaj)
        if not sifreli_mesaj:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "[!] Şifreleme başarısız oldu.")
            devam()

        gizli_resim = lsb.hide(resim_yolu, sifreli_mesaj)
        gizli_resim.save(cikti_dosyasi)

        print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] Mesaj başarıyla '{cikti_dosyasi}' dosyasına gömüldü.")
        devam()

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Resime mesaj gömme sırasında hata: {e}")
        devam()

# RESİMDEN MESAJ ÇIKARTMA
def mesaj_cikarma(resim_yolu):
    try:
        gizli_mesaj = lsb.reveal(resim_yolu)
        if not gizli_mesaj:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "[!] Resimde gizli mesaj tespit edilemedi!")
            devam()

        print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] Şifreli mesaj:\n{gizli_mesaj}\n")

        cozulmus_mesaj = sifre_coz(gizli_mesaj)
        if cozulmus_mesaj:
            print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] Çözülen mesaj:\n{cozulmus_mesaj}\n")
            kayit_edilsin_mi = input(Style.BRIGHT + Fore.LIGHTMAGENTA_EX + "[?] Çıktı 'gizlimesajlar.txt' dosyasına kayıt edilsin mi (y/n): ").strip().lower()
            if kayit_edilsin_mi.startswith("y"):
                dosya_kayit_et(cozulmus_mesaj)

            else:
                return main()

        else:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "[!] Şifreli mesaj çözülemedi.")
            devam()

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Resimden mesaj çıkarma sırasında hata: {e}")
        devam()


# CHARDET İLE DOSYA KODLAMASI ALGILAMA
def read_file_with_auto_encoding(file_path):
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            encoding = chardet.detect(raw_data)['encoding']
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
        
    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Genel hata: {e}")
        devam()

# GERİ DÖNÜŞTÜRÜLEN GİZLİ MESAJI DOSYAYA KAYIT ETME İŞLEMİ
def dosya_kayit_et(gizlimesaj):
    try:
        with open(f"gizlimesajlar.txt", "a", encoding="utf-8") as file:
            file.write(f"{gizlimesaj}\n")

        print(Style.BRIGHT + Fore.LIGHTGREEN_EX + "\n[+] 'gizlimesajlar.txt' dosyasına gizli mesaj kayıt edildi!")
        devam()

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"\n[!] Dosyaya kayıt hatası: {e}")
        devam()

# METNİ ASCİİ YE DÖNÜŞTÜR
def convert_to_ascii(message):
    try:
        ascii_message = message.encode('ascii', 'ignore').decode('ascii')
        if not ascii_message:
            raise ValueError(Style.BRIGHT + Fore.LIGHTRED_EX + "[!] Mesaj tamamen ASCII dışı karakterlerden oluşuyor!")
        return ascii_message
    
    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Metni ASCII'ye dönüştürme hatası: {e}")
        devam()

# MESAJI GÖRÜNMEZ YAP
def hide_message_in_invisible_chars(message):
    try:
        binary_message = ''.join(format(ord(c), '08b') for c in message)
        invisible_message = ''.join(' ' if bit == '1' else '\t' for bit in binary_message)
        return invisible_message
    
    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Metni ASCII'ye dönüştürme hatası: {e}")
        devam()

# MESAJI GÖRÜNÜR YAP
def extract_invisible_message(hidden_message):
    try:
        binary_message = ''.join('1' if char == ' ' else '0' for char in hidden_message if char in [' ', '\t'])
        decoded_message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
        return decoded_message
    
    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Metni ASCII'ye dönüştürme hatası: {e}")
        devam()

# MESAJ ŞİFRELEME BASE64
def encrypt_message(message):
    try:
        ascii_message = convert_to_ascii(message)
        if not ascii_message:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "[!] Mesaj şifrelenemiyor: Geçersiz karakterler.")
            devam()

        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(ascii_message.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
    
    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Metni ASCII'ye dönüştürme hatası: {e}")
        devam()

# MESAJ ŞİFRE ÇÖZME BASE64
def decrypt_message(encrypted_message):
    try:
        if len(encrypted_message) % 4 != 0:
            encrypted_message += '=' * (4 - len(encrypted_message) % 4)
            
        encrypted_bytes = base64.b64decode(encrypted_message)
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + f"[DEBUG] Base64 çözülmüş veri: {encrypted_bytes[:32]}...")
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + f"[DEBUG] Base64 çözüldü, toplam uzunluk: {len(encrypted_bytes)}")
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + f"[DEBUG] IV: {iv}, Şifreli metin: {ciphertext[:32]}...")
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + f"[DEBUG] IV uzunluğu: {len(iv)}, Ciphertext uzunluğu: {len(ciphertext)}")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_message.decode('utf-8')
    
    except ValueError as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Şifre çözme sırasında hata: Dosyada şifreli mesaj tespit edilemedi!")
        devam()

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Şifre çözme sırasında hata: {e}")
        devam()

# 1 DOSYAYA GİZLİ MESAJ YAZMA
def dosyaya_gizli_mesaj_yaz(dosya_yolu, mesaj):
    try:
        ascii_message = convert_to_ascii(mesaj)
        if not ascii_message:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "[!] Mesaj dosyaya yazılamadı: Geçersiz karakterler.")
            devam()

        hidden_message = hide_message_in_invisible_chars(encrypt_message(ascii_message))
        if hidden_message:
            with open(dosya_yolu, "a", encoding="utf-8") as dosya:
                dosya.write(hidden_message)
            print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] Mesaj '{dosya_yolu}' dosyasına başarıyla eklendi.")
            devam()

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Metni ASCII'ye dönüştürme hatası: {e}")
        devam()

# 2 DOSYADAN GİZLİ MESAJ OKUMA
def dosyadan_gizli_mesaj_oku(dosya_yolu):
    try:
        with open(dosya_yolu, "r", encoding="utf-8") as dosya:
            hidden_message = dosya.read()
            decrypted_message = decrypt_message(extract_invisible_message(hidden_message))
            if decrypted_message:
                print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] Gizli şifreli mesaj:\n\n{decrypted_message}")
                kayit_edilsin_mi = input(Style.BRIGHT + Fore.LIGHTMAGENTA_EX + "\n[?] Gizli mesajı 'gizlimesajlar.txt' dosyasına kayıt etmek istermisiniz (y/n): ").strip().lower()
                if kayit_edilsin_mi.startswith("y"):
                    dosya_kayit_et(decrypted_message)
                
                else:
                    return main()

            else:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + "\n[!] Mesaj çözülemedi.")
                devam()

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"\n[!] Genel hata: {e}")
        devam()

# ANA FONKSİYON
def main():
    try:
        sil()
        banner()
        menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
        [1] - Txt dosyasına gizli mesaj yaz
        [2] - Txt dosyasından gizli mesaj oku

        [3] - PNG dosyasına gizli mesaj yaz
        [4] - PNG dosyasından gizli mesaj oku
        
        [İ] - İletişim
        [Ç] - Çıkış
    """
        print(menu)
        secim = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Lütfen seçiminizi yapınız: ").strip().lower()

        if secim == "1" or secim.startswith("y"):
            sil()
            banner()
            dosya_yolu = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Lütfen dosyanın yolunu giriniz: ")
            mesaj = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Lütfen dosyanın içerisine yazılacak gizli mesajı giriniz: ")
            dosyaya_gizli_mesaj_yaz(dosya_yolu, mesaj)

        elif secim == "2" or secim.startswith("o"):
            sil()
            banner()
            dosya_yolu = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Lütfen dosyanın yolunu giriniz: ")
            sil()
            banner()
            dosyadan_gizli_mesaj_oku(dosya_yolu)

        elif secim == "3":
            sil()
            banner()
            dosya_yolu = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Lütfen dosyanın yolunu giriniz: ")
            mesaj = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Lütfen dosyanın içerisine yazılacak gizli mesajı giriniz: ")
            mesaj_gomme(dosya_yolu, mesaj, dosya_yolu)

        elif secim == "4":
            sil()
            banner()
            dosya_yolu = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Lütfen dosyanın yolunu giriniz: ")
            sil()
            banner()
            mesaj_cikarma(dosya_yolu)

        elif secim == "5" or secim.startswith("i"):
            sil()
            banner()
            contact()

        elif secim == "6" or secim.startswith("ç") or secim.startswith("q"):
            exit(0)

        else:
            return main()
            

    except Exception as e:
        print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[X] Genel hata: {e}")
        devam()

if __name__ == "__main__":
    main()
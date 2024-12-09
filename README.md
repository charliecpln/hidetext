# HideText
HideText, **txt** veya **jpg** dosyalarına **görünmez** ve **şifreli** şekilde gizli mesaj yazıp daha sonra o mesajı okumanıza olanak tanıyan bir Python aracıdır. Bu araç, metin dosyalarına veya resim dosyalarına mesaj gömme işlemini yaparken **AES şifreleme** ve  **Base64 kodlama** gibi güvenlik yöntemlerini kullanır.  

---

## **Özellikler**
- **Gizli Mesaj Gömme:**  
  - TXT dosyalarına şifreli ve görünmez karakterlerle mesaj ekleyin.  
  - JPG dosyalarına şifreli mesaj gömün (görsel bozulmadan).  

- **Gizli Mesaj Çıkarma:**  
  - TXT dosyalarından görünmez karakterlerle saklanan mesajları çıkarın.  
  - JPG dosyalarından şifrelenmiş mesajları çıkarın ve çözün.  

- **AES Şifreleme:**  
  - Mesajlar AES CBC modunda şifrelenir.  
  - Şifre çözme işlemi sırasında verinin bütünlüğü doğrulanır.  

- **Platform Desteği:**  
  - Windows, MacOS ve Linux üzerinde çalışır.

---

## **Kurulum**

### 1. Gerekli Kütüphanelerin Yüklenmesi
Programın içerisinde otomatik kurulum özelliği mevcuttur.  
Bu projeyi çalıştırmak için aşağıdaki Python kütüphanelerinin kurulu olması gerekmektedir:  

- Pillow
- pycryptodome
- stegano (JPG desteği için)

Kütüphaneleri yüklemek için aşağıdaki komutu kullanabilirsiniz veya direkt programı çalıştırıp otomatik kurulum özelliğinden faydanabilirsiniz:  
```bash
pip install -r requirements.txt

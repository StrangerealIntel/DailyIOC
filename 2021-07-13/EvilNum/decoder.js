encdata = "JEUdRhwAMF4bWDIpGXMTQiEDBVgXRXcxcjZVZg=="; // push the encoded data
a = window.atob(encdata)
c = a.length;
b = a.substring(c - 6);
a = a.substring(0, c - 6);
for (var c = "", d = 0; d < a.length; ++d)
{
	g = a.charCodeAt(d)
	e = b.charCodeAt(d % b.length)
	g = String.fromCharCode(g ^ e)
	c = c + g
}
console.log(c)

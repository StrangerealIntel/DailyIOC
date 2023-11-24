function Decode(arg)
{
	var r = "";
	for(var i = 0;i < arg.length;i += 2){r += String.fromCharCode(parseInt(arg.substr(i, 2), 16));}
	return(r);
}
function Rebuild(r)
{
	return(r.split("").reverse().join(""));
}
var d ="Push HexData";
u = Rebuild(d);
Data = Decode(u);
console.log(Data);

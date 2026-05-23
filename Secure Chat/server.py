"""
server.py  --  SecureChat Relay + HTTP Server
ECE 4304 Data Security Project

Serves index.html via HTTP and relays encrypted WebSocket messages.
Users who enter the same chat password are matched into the same private room.
The server only sees a SHA-256 hash of the password -- never the password itself.
"""

import asyncio, json, socket, threading, webbrowser, os, sys, subprocess, re
import http.server, socketserver

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
    from pyngrok import ngrok
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "websockets", "pyngrok"], check=True)
    import websockets
    from websockets.exceptions import ConnectionClosed
    from pyngrok import ngrok

PORT = 8080
rooms     = {}     # room_id (hash) -> [ws, ws]
ws_room   = {}     # ws -> room_id
lock      = asyncio.Lock()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

async def broadcast_room(room_id):
    """Tell all clients in a room how many peers are connected."""
    peers = rooms.get(room_id, [])
    msg   = json.dumps({"type": "status", "peers": len(peers)})
    for c in peers:
        try: await c.send(msg)
        except: pass

async def relay(ws):
    room_id = None
    try:
        # First message must be a join request with the hashed room ID
        raw = await asyncio.wait_for(ws.recv(), timeout=15)
        msg = json.loads(raw)

        if msg.get("type") != "join":
            await ws.close(); return

        room_id = msg.get("room", "")
        name = msg.get("name", "")
        if not room_id:
            await ws.close(); return

        async with lock:
            if room_id not in rooms:
                rooms[room_id] = []

            # Identify existing roles
            normal_users = [c for c in rooms[room_id] if getattr(c, 'is_attacker', False) == False]
            attackers    = [c for c in rooms[room_id] if getattr(c, 'is_attacker', False) == True]

            if name == "Attacker":
                if len(attackers) >= 1:
                    await ws.send(json.dumps({"type": "error", "msg": "Room already has an attacker."}))
                    await ws.close(); return
                ws.is_attacker = True
            else:
                if len(normal_users) >= 2:
                    # Try to become attacker if room is full
                    if len(attackers) >= 1:
                        await ws.send(json.dumps({"type": "error", "msg": "Room is full (2 users + 1 attacker present)."}))
                        await ws.close(); return
                    await ws.send(json.dumps({"type": "become_attacker"}))
                    ws.is_attacker = True
                else:
                    ws.is_attacker = False

            rooms[room_id].append(ws)
            ws_room[ws] = room_id
            
            # Legitimate users get host/guest roles; attackers just get 'attacker'
            if not ws.is_attacker:
                role = "host" if len(normal_users) == 0 else "guest"
                await ws.send(json.dumps({"type": "role", "role": role}))
            else:
                await ws.send(json.dumps({"type": "role", "role": "attacker"}))
                
            await broadcast_room(room_id)

        # Relay loop
        async for message in ws:
            async with lock:
                peers = [c for c in rooms.get(room_id, []) if c is not ws]
            for peer in peers:
                try: await peer.send(message)
                except: pass

    except (ConnectionClosed, asyncio.TimeoutError):
        pass
    except Exception as e:
        print(f"[relay error] {e}")
    finally:
        if room_id:
            async with lock:
                room = rooms.get(room_id, [])
                if ws in room: room.remove(ws)
                if not room and room_id in rooms: del rooms[room_id]
                ws_room.pop(ws, None)
                await broadcast_room(room_id)

async def process_request(connection, request=None):
    from websockets.http11 import Response
    from websockets.datastructures import Headers
    import http
    
    # Handle both websockets <14.0 (path, headers) and >=14.0 (connection, request)
    is_v14 = False
    if hasattr(request, "path"):
        is_v14 = True
        path = request.path
        headers = request.headers
    else:
        path = connection
        headers = request
        
    # Check if this is a WebSocket handshake request
    is_websocket = False
    if hasattr(headers, "get"):
        if "websocket" in str(headers.get("Upgrade", "")).lower():
            is_websocket = True
    elif headers is not None and "Upgrade" in headers:
        if "websocket" in str(headers["Upgrade"]).lower():
            is_websocket = True

    if is_websocket:
        return None  # Proceed to websocket handshake

    # Serve HTTP pages
    if path == "/" or path == "/index.html":
        with open("index.html", "rb") as f:
            body = f.read()
        if is_v14:
            return Response(200, "OK", Headers([("Content-Type", "text/html"), ("Content-Length", str(len(body)))]), body)
        return (http.HTTPStatus.OK, [("Content-Type", "text/html")], body)
    elif path == "/attacker" or path == "/attacker.html":
        with open("attacker.html", "rb") as f:
            body = f.read()
        if is_v14:
            return Response(200, "OK", Headers([("Content-Type", "text/html"), ("Content-Length", str(len(body)))]), body)
        return (http.HTTPStatus.OK, [("Content-Type", "text/html")], body)
        
    if is_v14:
        return Response(404, "Not Found", Headers([("Content-Type", "text/plain"), ("Content-Length", "9")]), b"Not Found")
    return (http.HTTPStatus.NOT_FOUND, [("Content-Type", "text/plain")], b"Not Found")

def start_tunnel():
    try:
        # Try to use the system ngrok if it exists in the standard WindowsApps location
        system_ngrok = r"C:\Users\NextGen\AppData\Local\Microsoft\WindowsApps\ngrok.exe"
        if os.path.exists(system_ngrok):
            from pyngrok import conf
            conf.get_default().ngrok_path = system_ngrok
            
        tunnel = ngrok.connect(PORT)
        url = tunnel.public_url
        print(f"\n  [TUNNEL] Public URL (Share this!): {url}")
        print(f"  [TUNNEL] Attacker View:            {url}/attacker.html\n")
    except Exception as e:
        err_msg = str(e).lower()
        if "authtoken" in err_msg or "authentication" in err_msg or "unauthorized" in err_msg:
            print(f"\n  [ERROR] Ngrok authentication failed or missing.")
            print(f"  Opening Ngrok dashboard so you can log in and copy your token.")
            print(f"  Run this command once you have your token: ngrok config add-authtoken <your-token>\n")
            webbrowser.open("https://dashboard.ngrok.com/get-started/your-authtoken")
        elif "already online" in err_msg:
            # Try to get the existing tunnel URL from local API
            try:
                import urllib.request
                with urllib.request.urlopen("http://localhost:4040/api/tunnels") as response:
                    data = json.loads(response.read().decode())
                    url = data['tunnels'][0]['public_url']
                    print(f"\n  [TUNNEL] Existing Public URL found: {url}")
                    print(f"  [TUNNEL] Attacker View:            {url}/attacker.html\n")
            except:
                print(f"Ngrok tunnel is already running, but could not retrieve URL automatically.")
        else:
            print(f"Failed to start Ngrok tunnel: {e}")

async def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Start localhost.run tunnel in background
    threading.Thread(target=start_tunnel, daemon=True).start()

    print("=" * 65)
    print("  [SECURE] SecureChat Server -- Multi-User Mode")
    print("=" * 65)
    print(f"  Local URL:                http://localhost:{PORT}")
    print(f"  Attacker View (Local):    http://localhost:{PORT}/attacker.html")
    print(f"\n  Waiting for Ngrok to generate public URL...")
    print(f"\n  All devices use the same Chat Password to join the room.")
    print(f"  Press Ctrl+C to stop.\n" + "=" * 65)

    webbrowser.open(f"http://localhost:{PORT}/index.html")

    async with websockets.serve(relay, "0.0.0.0", PORT, process_request=process_request, max_size=2**25, ping_interval=None, ping_timeout=None):
        await asyncio.Future()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\nServer stopped.")

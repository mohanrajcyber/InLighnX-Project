const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const pty = require('node-pty');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const LOG_FILE = 'student_sessions.log';
app.use(express.static('public'));

const ALLOWED_PROJECTS = ['Bounty', 'CyberXploit', 'zerotraceX', 'Hash'];
const PROJECTS_DIR = path.join(__dirname, 'projects');

function getLocalIP() {
    const ifaces = os.networkInterfaces();
    for (const iface of Object.values(ifaces)) {
        for (const details of iface) {
            if (details.family === 'IPv4' && !details.internal) return details.address;
        }
    }
    return '127.0.0.1';
}
const LOCAL_IP = getLocalIP();

// Auto detect free port (safe for browsers)
async function getFreePort(start = 3000, end = 5000) {
    for (let port = start; port <= end; port++) {
        const isFree = await new Promise(resolve => {
            const tester = net.createServer()
                .once('error', () => resolve(false))
                .once('listening', () => tester.close(() => resolve(true)))
                .listen(port, LOCAL_IP);
        });
        if (isFree) return port;
    }
    return 3000; // fallback
}

// Start server
(async () => {
    const PORT = await getFreePort();
    server.listen(PORT, LOCAL_IP, () => {
        console.log(`✅ Web Terminal running at http://${LOCAL_IP}:${PORT}`);
    });
})();

// Socket.io connection
io.on('connection', (socket) => {
    const studentIP = socket.handshake.address;
    console.log(`👤 Student connected: ${studentIP}`);

    const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';
    const ptyProcess = pty.spawn(shell, [], {
        name: 'xterm-color',
        cols: 80,
        rows: 24,
        cwd: PROJECTS_DIR,
        env: process.env
    });

    ptyProcess.on('data', (data) => socket.emit('output', data));

    socket.on('input', (data) => {
        const trimmed = data.trim();
        const forbidden = ['sudo', 'rm ', 'mv ', 'cp '];

        if (trimmed === 'exit') {
            ptyProcess.kill();
            socket.disconnect();
            return;
        }

        if (trimmed.startsWith('cd ')) {
            const target = trimmed.split(' ')[1]?.trim();
            if (!ALLOWED_PROJECTS.includes(target)) {
                socket.emit('output', "\r\n🚫 Only allowed project folders!\r\n");
                return;
            }
        }

        if (forbidden.some(cmd => trimmed.includes(cmd))) {
            socket.emit('output', "\r\n⚠️ Command blocked\r\n");
            return;
        }

        ptyProcess.write(data);

        if (data.includes('\r') || data.includes('\n')) {
            const logEntry = `${new Date().toISOString()} [${studentIP}] ${data.replace(/\r|\n/g,'')}\n`;
            fs.appendFileSync(LOG_FILE, logEntry);
        }
    });

    socket.on('disconnect', () => {
        console.log(`❌ Student disconnected: ${studentIP}`);
        try { ptyProcess.kill(); } catch {}
    });
});

// Provide IP and projects to frontend
app.get('/active-port', async (req, res) => {
    const PORT = server.address().port;
    res.json({ ip: LOCAL_IP, port: PORT, projects: ALLOWED_PROJECTS });
});

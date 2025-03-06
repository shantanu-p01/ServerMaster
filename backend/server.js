import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import CryptoJS from 'crypto-js';
import dotenv from 'dotenv';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Client } from 'ssh2';

// Import from our modules
import { User, connectDB, formatDate, cache } from './models.js';
import { 
  decryptAESData, 
  decryptSSHPassword,
  getSSHConnection,
  getConnectionKey,
  createSSHConfig,
  createExecPromise,
  cleanupSSHConnections,
  sshConnectionPool
} from './utils.js';

// Setup directory path for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { 
    success: false, 
    message: 'Too many requests, please try again later.' 
  }
});

app.use('/api/auth', limiter); 
app.use('/api/validate-auth', limiter);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  },
  crossOriginResourcePolicy: { policy: 'same-site' },
  dnsPrefetchControl: { allow: false },
  referrerPolicy: { policy: 'no-referrer' }
}));

// Performance middleware
app.use(compression({ level: 6 }));
app.use(cors());
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch(e) {
      res.status(400).send({ 
        success: false, 
        message: 'Invalid JSON payload' 
      });
      throw new Error('Invalid JSON');
    }
  }
}));

// Connect to MongoDB
connectDB();

// Cleanup for idle SSH connections
setInterval(cleanupSSHConnections, 60 * 1000);

// Authentication endpoint
app.post('/api/auth', async (req, res) => {
  const startTime = Date.now();
  try {
    const { auth, email, password, username } = req.body;
    const deviceToken = req.headers['x-device-token'];
    const publicIP = req.headers['x-public-ip'] || 'Unknown';
    
    if (!auth || !email || !password) {
      return res.status(400).json({ 
        message: 'Missing required authentication fields' 
      });
    }

    if (!deviceToken) {
      return res.status(400).json({ 
        message: 'Device token is required' 
      });
    }

    const [decryptedPassword, decryptedDeviceToken] = await Promise.all([
      Promise.resolve(decryptAESData(password, process.env.AES_AUTH_PASSWORD_KEY)),
      Promise.resolve(decryptAESData(deviceToken, process.env.AES_AUTH_PASSWORD_KEY))
    ]);
    
    if (!decryptedPassword) {
      return res.status(400).json({ 
        message: 'Password decryption failed' 
      });
    }

    if (!decryptedDeviceToken) {
      return res.status(400).json({ 
        message: 'Device token decryption failed' 
      });
    }

    if (auth === 'signup') {
      if (!username) {
        return res.status(400).json({ 
          message: 'Username is required for signup' 
        });
      }

      const existingUser = await User.findOne({ 
        $or: [
          { email: email.toLowerCase() }, 
          { username: username }
        ]
      }).lean();

      if (existingUser) {
        return res.status(409).json({ 
          message: existingUser.email === email.toLowerCase() 
            ? 'Email already exists' 
            : 'Username already exists' 
        });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(decryptedPassword, salt);

      const newUser = new User({
        username,
        email: email.toLowerCase(),
        password: hashedPassword,
        deviceToken,
        loginIp: publicIP,
        lastLoginTime: null,
        createdAt: formatDate()
      });

      await newUser.save();

      console.log(`Signup completed in ${Date.now() - startTime}ms`);
      
      return res.status(201).json({ 
        message: 'User registered successfully',
        username: newUser.username,
        email: newUser.email
      });
    }

    if (auth === 'signin') {
      const user = await User.findOne({ email: email.toLowerCase() })
                             .select('username email password deviceToken loginIp lastLoginTime');

      if (!user) {
        return res.status(404).json({ 
          message: 'User not found' 
        });
      }

      const isMatch = await bcrypt.compare(decryptedPassword, user.password);

      if (!isMatch) {
        return res.status(401).json({ 
          message: 'Invalid credentials' 
        });
      }

      await User.updateOne(
        { _id: user._id },
        {
          $set: {
            deviceToken: deviceToken,
            loginIp: publicIP,
            lastLoginTime: formatDate()
          }
        }
      );

      console.log(`Signin completed in ${Date.now() - startTime}ms`);
      
      return res.status(200).json({ 
        message: 'Login successful',
        username: user.username,
        email: user.email
      });
    }

    return res.status(400).json({ 
      message: 'Invalid authentication type' 
    });

  } catch (error) {
    console.error('Authentication error:', error);
    console.log(`Auth error occurred after ${Date.now() - startTime}ms`);
    
    res.status(500).json({ 
      message: 'Server error during authentication',
      error: error.message 
    });
  }
});

// Authentication validation endpoint
app.post('/api/validate-auth', async (req, res) => {
    const startTime = Date.now();
    
    try {
      const { email, username } = req.body;
      const deviceToken = req.headers['x-device-token'];
      
      console.log('Validating auth for:', { email, username });
      
      const tokenHash = deviceToken ? 
        CryptoJS.MD5(deviceToken).toString().substring(0, 10) : 
        'none';
      const cacheKey = `auth_${email}_${username}_${tokenHash}`;
      const cachedResult = cache.get(cacheKey);
      
      if (cachedResult) {
        console.log(`Auth validation from cache completed in ${Date.now() - startTime}ms`);
        return res.status(200).json(cachedResult);
      }
      
      if (!email || !username || !deviceToken) {
        console.log('Missing required auth fields');
        return res.status(400).json({ 
          message: 'Missing required authentication fields',
          valid: false
        });
      }
  
      const decryptedDeviceToken = decryptAESData(deviceToken, process.env.AES_AUTH_PASSWORD_KEY);
      
      if (!decryptedDeviceToken) {
        console.log('Device token decryption failed');
        return res.status(400).json({ 
          message: 'Device token decryption failed',
          valid: false
        });
      }
      
      const user = await User.findOne({ 
        email: email.toLowerCase(),
        username
      }).lean();
  
      if (!user) {
        console.log('User not found');
        return res.status(404).json({ 
          message: 'User not found',
          valid: false
        });
      }
  
      console.log('Updating device token in database');
      
      await User.updateOne(
        { _id: user._id },
        {
          $set: {
            deviceToken: deviceToken,
            lastLoginTime: formatDate()
          }
        }
      );
  
      const response = { 
        message: 'Authentication validated successfully',
        valid: true
      };
      
      cache.set(cacheKey, response, 30);
      
      console.log(`Auth validation completed in ${Date.now() - startTime}ms`);
      return res.status(200).json(response);
  
    } catch (error) {
      console.error('Authentication validation error:', error);
      console.log(`Auth validation error after ${Date.now() - startTime}ms`);
      
      res.status(500).json({ 
        message: 'Server error during authentication validation',
        error: error.message,
        valid: false
      });
    }
});

// SSH connection endpoint
app.post('/api/connect', async (req, res) => {
  const startTime = Date.now();
  let conn = null;
  const { username, ipAddress, authMethod, password, keyFileContent, keyFileName } = req.body;
  const connectionKey = getConnectionKey(username, ipAddress, authMethod);
  
  try {
    if (!username || !ipAddress) {
      return res.status(400).json({
        success: false,
        message: 'Missing SSH connection details (username or IP address)'
      });
    }
    
    if (!authMethod || (authMethod !== 'password' && authMethod !== 'key')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid authentication method'
      });
    }
    
    if (authMethod === 'password' && !password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required for password authentication'
      });
    }
    
    if (authMethod === 'key' && !keyFileContent) {
      return res.status(400).json({
        success: false,
        message: 'Key file content is required for key authentication'
      });
    }
    
    let decryptedPassword = null;
    let decryptedKeyContent = null;
    
    if (authMethod === 'password') {
      decryptedPassword = decryptSSHPassword(password);
      if (!decryptedPassword) {
        return res.status(400).json({
          success: false,
          message: 'Failed to decrypt SSH password'
        });
      }
    } else {
      decryptedKeyContent = decryptSSHPassword(keyFileContent);
      if (!decryptedKeyContent) {
        return res.status(400).json({
          success: false,
          message: 'Failed to decrypt SSH key file'
        });
      }
    }
    
    const connectionConfig = createSSHConfig(
      username, 
      ipAddress, 
      authMethod, 
      decryptedPassword, 
      decryptedKeyContent, 
      keyFileName
    );
    
    conn = await getSSHConnection(connectionConfig);
    
    const execPromise = createExecPromise(conn, decryptedPassword, authMethod);
    
    const osTypeCommand = `cat /etc/os-release 2>/dev/null | grep -E '^ID=' | cut -d'=' -f2 | tr -d '"'`;
    const osType = await execPromise(osTypeCommand);
    
    if (sshConnectionPool.has(connectionKey)) {
      sshConnectionPool.get(connectionKey).lastUsed = Date.now();
    }
    
    console.log(`SSH connect completed in ${Date.now() - startTime}ms`);
    
    return res.status(200).json({
      success: true,
      osType: osType
    });
    
  } catch (error) {
    console.error('SSH connection error:', error);
    console.log(`SSH connect error after ${Date.now() - startTime}ms`);
    
    if (sshConnectionPool.has(connectionKey)) {
      try {
        const pooledConn = sshConnectionPool.get(connectionKey).conn;
        pooledConn.end();
      } catch (e) {
        // Ignore errors during cleanup
      }
      sshConnectionPool.delete(connectionKey);
    }
    
    return res.status(500).json({
      success: false,
      message: error.level === 'client-authentication' 
        ? 'Authentication failed. Please check your credentials.' 
        : error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED'  
          ? 'Connection timed out. Please verify the server address and try again.' 
          : 'Failed to connect to server',
      error: error.message
    });
  }
});

// SSH monitoring endpoint
app.post('/api/monitor', async (req, res) => {
  const startTime = Date.now();
  let conn = null;
  const { username, ipAddress, authMethod, password, keyFileContent, keyFileName } = req.body;
  const connectionKey = getConnectionKey(username, ipAddress, authMethod);
  
  try {
    if (!username || !ipAddress) {
      return res.status(400).json({
        success: false,
        message: 'Missing SSH connection details (username or IP address)'
      });
    }
    
    if (!authMethod || (authMethod !== 'password' && authMethod !== 'key')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid authentication method'
      });
    }
    
    if (authMethod === 'password' && !password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required for password authentication'
      });
    }
    
    if (authMethod === 'key' && !keyFileContent) {
      return res.status(400).json({
        success: false,
        message: 'Key file content is required for key authentication'
      });
    }
    
    let decryptedPassword = null;
    let decryptedKeyContent = null;
    
    if (authMethod === 'password') {
      decryptedPassword = decryptSSHPassword(password);
      if (!decryptedPassword) {
        return res.status(400).json({
          success: false,
          message: 'Failed to decrypt SSH password'
        });
      }
    } else {
      decryptedKeyContent = decryptSSHPassword(keyFileContent);
      if (!decryptedKeyContent) {
        return res.status(400).json({
          success: false,
          message: 'Failed to decrypt SSH key file'
        });
      }
    }
    
    const connectionConfig = createSSHConfig(
      username, 
      ipAddress, 
      authMethod, 
      decryptedPassword, 
      decryptedKeyContent, 
      keyFileName
    );
    
    conn = await getSSHConnection(connectionConfig);
    
    const execPromise = createExecPromise(conn, decryptedPassword, authMethod);
    
    const cpuInfoCommand = "cat /proc/cpuinfo | grep 'model name' | head -1 && top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}'";
    const memoryInfoCommand = "free -h | grep 'Mem:' | awk '{print $2, $3}'";
    const processesCommand = "ps aux | awk '{print $2, $1, $3, $4, $11}'";
    const loadCommand = "uptime | awk -F'load average:' '{print $2}'";
    
    const [cpuInfo, memoryInfo, processesOutput, systemLoad] = await Promise.all([
      execPromise(cpuInfoCommand),
      execPromise(memoryInfoCommand),
      execPromise(processesCommand),
      execPromise(loadCommand)
    ]);
    
    const [cpuModel, cpuUsage] = cpuInfo.split('\n');
    const [totalMemory, usedMemory] = memoryInfo.split(' ');
    
    const processes = processesOutput.split('\n')
      .slice(1)
      .map(process => {
        const [pid, user, cpu, memory, command] = process.split(' ');
        return { pid, user, cpu, memory, command };
      });
    
    const [load1m, load5m, load15m] = systemLoad.trim().split(',').map(load => load.trim());
    
    if (sshConnectionPool.has(connectionKey)) {
      sshConnectionPool.get(connectionKey).lastUsed = Date.now();
    }
    
    console.log(`SSH monitoring completed in ${Date.now() - startTime}ms`);
    
    return res.status(200).json({
      success: true,
      cpuInfo: {
        model: cpuModel.replace('model name\t: ', ''),
        usage: parseFloat(cpuUsage).toFixed(2)
      },
      memoryInfo: {
        total: totalMemory,
        used: usedMemory
      },
      processes,
      systemLoad: {
        '1m': load1m,
        '5m': load5m,
        '15m': load15m
      }
    });
    
  } catch (error) {
    console.error('Monitoring error:', error);
    console.log(`SSH monitoring error after ${Date.now() - startTime}ms`);
    
    if (sshConnectionPool.has(connectionKey)) {
      try {
        const pooledConn = sshConnectionPool.get(connectionKey).conn;
        pooledConn.end();
      } catch (e) {
        // Ignore errors during cleanup
      }
      sshConnectionPool.delete(connectionKey);
    }
    
    return res.status(500).json({
      success: false,
      message: error.level === 'client-authentication' 
        ? 'Authentication failed. Please check your credentials.' 
        : error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED'  
          ? 'Connection timed out. Please verify the server address and try again.' 
          : 'Failed to retrieve monitoring data',
      error: error.message
    });
  }
});

// Command execution endpoint
app.post('/api/execute-command', async (req, res) => {
  const startTime = Date.now();
  let conn = null;
  const { 
    username, 
    ipAddress, 
    authMethod, 
    command, 
    password, 
    keyFileContent, 
    keyFileName,
    useSudo = false
  } = req.body;
  const connectionKey = getConnectionKey(username, ipAddress, authMethod);
  
  try {
    if (!username || !ipAddress || !command) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields (username, IP address, or command)'
      });
    }
    
    if (!authMethod || (authMethod !== 'password' && authMethod !== 'key')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid authentication method'
      });
    }
    
    if (authMethod === 'password' && !password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required for password authentication'
      });
    }
    
    if (authMethod === 'key' && !keyFileContent) {
      return res.status(400).json({
        success: false,
        message: 'Key file content is required for key authentication'
      });
    }
    
    let decryptedPassword = null;
    let decryptedKeyContent = null;
    
    try {
      if (authMethod === 'password') {
        decryptedPassword = decryptSSHPassword(password);
        if (!decryptedPassword) {
          throw new Error('Failed to decrypt SSH password');
        }
      } else {
        decryptedKeyContent = decryptSSHPassword(keyFileContent);
        if (!decryptedKeyContent) {
          throw new Error('Failed to decrypt SSH key file');
        }
      }
    } catch (decryptError) {
      return res.status(400).json({
        success: false,
        message: decryptError.message
      });
    }
    
    const connectionConfig = createSSHConfig(
      username, 
      ipAddress, 
      authMethod, 
      decryptedPassword, 
      decryptedKeyContent, 
      keyFileName
    );
    
    conn = await getSSHConnection(connectionConfig);
    
    const execPromise = createExecPromise(conn, decryptedPassword, authMethod);
    
    const output = await execPromise(command, { useSudo });
    
    if (sshConnectionPool.has(connectionKey)) {
      sshConnectionPool.get(connectionKey).lastUsed = Date.now();
    }
    
    console.log(`SSH execute command completed in ${Date.now() - startTime}ms`);
    
    return res.status(200).json({
      success: true,
      output
    });
    
  } catch (error) {
    console.error('SSH command execution error:', error);
    console.log(`SSH execute command error after ${Date.now() - startTime}ms`);
    
    if (sshConnectionPool.has(connectionKey)) {
      try {
        const pooledConn = sshConnectionPool.get(connectionKey).conn;
        pooledConn.end();
      } catch (e) {
        // Ignore errors during cleanup
      }
      sshConnectionPool.delete(connectionKey);
    }
    
    if (error.level === 'client-authentication') {
      return res.status(401).json({
        success: false,
        message: 'Authentication failed. Please check your credentials.'
      });
    }
    
    if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        success: false,
        message: 'Connection timed out. Please verify the server address and try again.'
      });
    }
    
    if (error.message.includes('sudo')) {
      return res.status(403).json({
        success: false,
        message: 'Sudo access denied. Ensure you have the necessary privileges.'
      });
    }
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to execute command',
      error: error.toString()
    });
  }
});

// Script execution endpoint
app.post('/api/execute-script', async (req, res) => {
  const startTime = Date.now();
  let conn = null;
  const { 
    username, 
    ipAddress, 
    authMethod, 
    scriptContent, 
    password, 
    keyFileContent, 
    keyFileName,
    useSudo = false
  } = req.body;
  const connectionKey = getConnectionKey(username, ipAddress, authMethod);
  
  try {
    if (!username || !ipAddress || !scriptContent) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields (username, IP address, or script content)'
      });
    }
    
    if (!authMethod || (authMethod !== 'password' && authMethod !== 'key')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid authentication method'
      });
    }
    
    if (authMethod === 'password' && !password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required for password authentication'
      });
    }
    
    if (authMethod === 'key' && !keyFileContent) {
      return res.status(400).json({
        success: false,
        message: 'Key file content is required for key authentication'
      });
    }
    
    let decryptedPassword = null;
    let decryptedKeyContent = null;
    
    try {
      if (authMethod === 'password') {
        decryptedPassword = decryptSSHPassword(password);
        if (!decryptedPassword) {
          throw new Error('Failed to decrypt SSH password');
        }
      } else {
        decryptedKeyContent = decryptSSHPassword(keyFileContent);
        if (!decryptedKeyContent) {
          throw new Error('Failed to decrypt SSH key file');
        }
      }
    } catch (decryptError) {
      return res.status(400).json({
        success: false,
        message: decryptError.message
      });
    }
    
    const connectionConfig = createSSHConfig(
      username, 
      ipAddress, 
      authMethod, 
      decryptedPassword, 
      decryptedKeyContent, 
      keyFileName
    );
    
    conn = await getSSHConnection(connectionConfig);
    
    const execPromise = createExecPromise(conn, decryptedPassword, authMethod);
    
    const timestamp = Date.now();
    const scriptFileName = `/tmp/custom_script_${timestamp}_${Math.floor(Math.random() * 10000)}.sh`;
    
    try {
      await new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) return reject(err);
          
          const writeStream = sftp.createWriteStream(scriptFileName);
          writeStream.on('error', reject);
          writeStream.on('close', resolve);
          writeStream.write(scriptContent);
          writeStream.end();
        });
      });
      
      await execPromise(`chmod +x ${scriptFileName}`);
      
      let output;
      if (useSudo) {
        if (authMethod === 'password') {
          output = await execPromise(`echo "${decryptedPassword}" | sudo -S ${scriptFileName}`);
        } else {
          output = await execPromise(`sudo ${scriptFileName}`);
        }
      } else {
        output = await execPromise(scriptFileName);
      }
      
      await execPromise(`rm -f ${scriptFileName}`);
      
      if (sshConnectionPool.has(connectionKey)) {
        sshConnectionPool.get(connectionKey).lastUsed = Date.now();
      }
      
      console.log(`SSH execute script completed in ${Date.now() - startTime}ms`);
      
      return res.status(200).json({
        success: true,
        output
      });
    } catch (error) {
      try {
        await execPromise(`rm -f ${scriptFileName}`);
      } catch {}
      
      throw error;
    }
    
  } catch (error) {
    console.error('Script execution error:', error);
    console.log(`SSH execute script error after ${Date.now() - startTime}ms`);
    
    if (sshConnectionPool.has(connectionKey)) {
      try {
        const pooledConn = sshConnectionPool.get(connectionKey).conn;
        pooledConn.end();
      } catch (e) {
        // Ignore errors during cleanup
      }
      sshConnectionPool.delete(connectionKey);
    }
    
    if (error.level === 'client-authentication') {
      return res.status(401).json({
        success: false,
        message: 'Authentication failed. Please check your credentials.'
      });
    }
    
    if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        success: false,
        message: 'Connection timed out. Please verify the server address and try again.'
      });
    }
    
    if (error.message.includes('sudo')) {
      return res.status(403).json({
        success: false,
        message: 'Sudo access denied. Ensure you have the necessary privileges.'
      });
    }
    
    return res.status(500).json({
        success: false,
        message: error.message || 'Failed to execute script',
        error: error.toString()
    });
  }
});

// Application check endpoint
app.post('/api/check-installed', async (req, res) => {
  const startTime = Date.now();
  let conn = null;
  const { 
    username, 
    ipAddress, 
    authMethod, 
    password, 
    keyFileContent, 
    keyFileName
  } = req.body;
  const connectionKey = getConnectionKey(username, ipAddress, authMethod);
  
  try {
    if (!username || !ipAddress) {
      return res.status(400).json({
        success: false,
        message: 'Missing SSH connection details (username or IP address)'
      });
    }
    
    if (!authMethod || (authMethod !== 'password' && authMethod !== 'key')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid authentication method'
      });
    }
    
    if (authMethod === 'password' && !password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required for password authentication'
      });
    }
    
    if (authMethod === 'key' && !keyFileContent) {
      return res.status(400).json({
        success: false,
        message: 'Key file content is required for key authentication'
      });
    }
    
    let decryptedPassword = null;
    let decryptedKeyContent = null;
    
    try {
      if (authMethod === 'password') {
        decryptedPassword = decryptSSHPassword(password);
        if (!decryptedPassword) {
          throw new Error('Failed to decrypt SSH password');
        }
      } else {
        decryptedKeyContent = decryptSSHPassword(keyFileContent);
        if (!decryptedKeyContent) {
          throw new Error('Failed to decrypt SSH key file');
        }
      }
    } catch (decryptError) {
      return res.status(400).json({
        success: false,
        message: decryptError.message
      });
    }
    
    const connectionConfig = createSSHConfig(
      username, 
      ipAddress, 
      authMethod, 
      decryptedPassword, 
      decryptedKeyContent, 
      keyFileName
    );
    
    conn = await getSSHConnection(connectionConfig);
    
    const execPromise = createExecPromise(conn, decryptedPassword, authMethod);
    
    const checkVersionCommands = {
      docker: "docker --version 2>/dev/null || echo 'Not installed'",
      nginx: "nginx -v 2>&1 || echo 'Not installed'",
      caddy: "caddy version 2>/dev/null || echo 'Not installed'",
      apache2: "(apache2 -v 2>/dev/null || httpd -v 2>/dev/null) || echo 'Not installed'",
      awsCli: "aws --version 2>/dev/null || echo 'Not installed'"
    };
    
    const installedStatus = {};
    
    const checkPromises = Object.entries(checkVersionCommands).map(async ([app, cmd]) => {
      try {
        const result = await execPromise(cmd, { returnCode: true });
        
        installedStatus[app] = {
          installed: !result.output.includes('Not installed') && result.code === 0,
          version: result.output.trim().replace(/^(.*?)\s*$/, '$1')
        };
      } catch (error) {
        installedStatus[app] = {
          installed: false,
          version: 'Error checking version'
        };
      }
    });
    
    await Promise.all(checkPromises);
    
    if (sshConnectionPool.has(connectionKey)) {
      sshConnectionPool.get(connectionKey).lastUsed = Date.now();
    }
    
    console.log(`SSH check installed completed in ${Date.now() - startTime}ms`);
    
    return res.status(200).json({
      success: true,
      installed: installedStatus
    });
    
  } catch (error) {
    console.error('Error checking installed applications:', error);
    console.log(`SSH check installed error after ${Date.now() - startTime}ms`);
    
    if (sshConnectionPool.has(connectionKey)) {
      try {
        const pooledConn = sshConnectionPool.get(connectionKey).conn;
        pooledConn.end();
      } catch (e) {
        // Ignore errors during cleanup
      }
      sshConnectionPool.delete(connectionKey);
    }
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to check installed applications',
      error: error.toString()
    });
  }
});

// Application installation endpoint
app.post('/api/install', async (req, res) => {
  const startTime = Date.now();
  let conn = null;
  const { 
    username, 
    ipAddress, 
    authMethod, 
    password, 
    keyFileContent, 
    keyFileName,
    applications
  } = req.body;
  const connectionKey = getConnectionKey(username, ipAddress, authMethod);
  
  try {
    if (!username || !ipAddress || !applications || !Array.isArray(applications) || applications.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields (username, IP address, or applications array)'
      });
    }
    
    const supportedApps = ['docker', 'nginx', 'caddy', 'apache2', 'awsCli'];
    const invalidApps = applications.filter(app => !supportedApps.includes(app));
    if (invalidApps.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Unsupported application(s): ${invalidApps.join(', ')}`
      });
    }
    
    if (!authMethod || (authMethod !== 'password' && authMethod !== 'key')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid authentication method'
      });
    }
    
    if (authMethod === 'password' && !password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required for password authentication'
      });
    }
    
    if (authMethod === 'key' && !keyFileContent) {
      return res.status(400).json({
        success: false,
        message: 'Key file content is required for key authentication'
      });
    }
    
    let decryptedPassword = null;
    let decryptedKeyContent = null;
    
    try {
      if (authMethod === 'password') {
        decryptedPassword = decryptSSHPassword(password);
        if (!decryptedPassword) {
          throw new Error('Failed to decrypt SSH password');
        }
      } else {
        decryptedKeyContent = decryptSSHPassword(keyFileContent);
        if (!decryptedKeyContent) {
          throw new Error('Failed to decrypt SSH key file');
        }
      }
    } catch (decryptError) {
      return res.status(400).json({
        success: false,
        message: decryptError.message
      });
    }
    
    const connectionConfig = createSSHConfig(
      username, 
      ipAddress, 
      authMethod, 
      decryptedPassword, 
      decryptedKeyContent, 
      keyFileName
    );
    
    conn = await getSSHConnection(connectionConfig);
    
    const execPromise = createExecPromise(conn, decryptedPassword, authMethod);
    
    const scriptPromises = applications.map(async (application) => {
      try {
        const scriptPath = path.join(__dirname, 'scripts', `${application}.sh`);
        return {
          application,
          content: await fs.promises.readFile(scriptPath, 'utf8')
        };
      } catch (scriptError) {
        console.error(`Error reading script file for ${application}:`, scriptError);
        return {
          application,
          error: `Installation script for ${application} not found or cannot be read`
        };
      }
    });
    
    const scripts = await Promise.all(scriptPromises);
    const results = [];
    
    for (const scriptResult of scripts) {
      try {
        if (scriptResult.error) {
          results.push({
            application: scriptResult.application,
            success: false,
            message: scriptResult.error
          });
          continue;
        }
        
        const application = scriptResult.application;
        const scriptContent = scriptResult.content;
        const tempScriptPath = `/tmp/${application}_install_${Date.now()}.sh`;
        
        await new Promise((resolve, reject) => {
          conn.sftp((err, sftp) => {
            if (err) return reject(err);
            
            const writeStream = sftp.createWriteStream(tempScriptPath);
            writeStream.on('error', reject);
            writeStream.on('close', resolve);
            writeStream.write(scriptContent);
            writeStream.end();
          });
        });
        
        await execPromise(`chmod +x ${tempScriptPath}`);
        
        let output;
        try {
          if (authMethod === 'password') {
            console.log(`Executing ${application} install with password-based sudo`);
            output = await execPromise(`echo "${decryptedPassword}" | sudo -S ${tempScriptPath}`);
          } else {
            output = await execPromise(`sudo ${tempScriptPath}`);
          }
        } catch (installError) {
          try {
            await execPromise(`rm -f ${tempScriptPath}`);
          } catch {}
          
          results.push({
            application,
            success: false,
            message: installError.message || `Failed to install ${application}`
          });
          continue;
        }
        
        await execPromise(`rm -f ${tempScriptPath}`);
        
        results.push({
          application,
          success: true,
          message: `${application} has been successfully installed`
        });
        
      } catch (appError) {
        results.push({
          application: scriptResult.application,
          success: false,
          message: appError.message || `Failed to install ${scriptResult.application}`
        });
      }
    }
    
    if (sshConnectionPool.has(connectionKey)) {
      sshConnectionPool.get(connectionKey).lastUsed = Date.now();
    }
    
    console.log(`SSH install apps completed in ${Date.now() - startTime}ms`);
    
    const overallSuccess = results.some(result => result.success);
    
    return res.status(overallSuccess ? 200 : 500).json({
      success: overallSuccess,
      results: results
    });
    
  } catch (error) {
    console.error('Installation error:', error);
    console.log(`SSH install apps error after ${Date.now() - startTime}ms`);
    
    if (sshConnectionPool.has(connectionKey)) {
      try {
        const pooledConn = sshConnectionPool.get(connectionKey).conn;
        pooledConn.end();
      } catch (e) {
        // Ignore errors during cleanup
      }
      sshConnectionPool.delete(connectionKey);
    }
    
    if (error.level === 'client-authentication') {
      return res.status(401).json({
        success: false,
        message: 'Authentication failed. Please check your credentials.'
      });
    }
    
    if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        success: false,
        message: 'Connection timed out. Please verify the server address and try again.'
      });
    }
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to install applications',
      error: error.toString()
    });
  }
});

// Connection verification endpoint
app.post('/api/verify-connection', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { username, ipAddress, authMethod, password, keyFileContent, keyFileName, verifyOnly } = req.body;
    
    const cacheKey = `verify_${username}@${ipAddress}_${authMethod}_${Date.now() > 0}`;
    const cachedResult = cache.get(cacheKey);
    
    if (cachedResult && verifyOnly) {
      console.log(`SSH verify from cache completed in ${Date.now() - startTime}ms`);
      return res.status(200).json(cachedResult);
    }
    
    if (!username || !ipAddress) {
      return res.status(400).json({
        success: false,
        message: 'Missing SSH connection details (username or IP address)'
      });
    }
    
    if (!authMethod || (authMethod !== 'password' && authMethod !== 'key')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid authentication method'
      });
    }
    
    if (authMethod === 'password' && !password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required for password authentication'
      });
    }
    
    if (authMethod === 'key' && !keyFileContent) {
      return res.status(400).json({
        success: false,
        message: 'Key file content is required for key authentication'
      });
    }
    
    let decryptedPassword = null;
    let decryptedKeyContent = null;
    
    if (authMethod === 'password') {
      decryptedPassword = decryptSSHPassword(password);
      if (!decryptedPassword) {
        return res.status(400).json({
          success: false,
          message: 'Failed to decrypt SSH password'
        });
      }
    } else {
      decryptedKeyContent = decryptSSHPassword(keyFileContent);
      if (!decryptedKeyContent) {
        return res.status(400).json({
          success: false,
          message: 'Failed to decrypt SSH key file'
        });
      }
    }
    
    const conn = new Client();
    
    const connectionConfig = {
      host: ipAddress,
      port: 22,
      username: username,
      readyTimeout: 10000,
      algorithms: {
        serverHostKey: ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
      }
    };
    
    if (authMethod === 'password') {
      connectionConfig.password = decryptedPassword;
    } else {
      const isPPK = keyFileName && keyFileName.toLowerCase().endsWith('.ppk');
      
      if (isPPK) {
        connectionConfig.privateKey = decryptedKeyContent;
        connectionConfig.passphrase = '';
      } else {
        connectionConfig.privateKey = decryptedKeyContent;
        connectionConfig.passphrase = '';
      }
    }
    
    const connectPromise = () => {
      return new Promise((resolve, reject) => {
        conn.on('ready', () => resolve())
            .on('error', (err) => reject(err))
            .connect(connectionConfig);
      });
    };
    
    await connectPromise();
    
    conn.end();
    
    const response = {
      success: true,
      message: 'SSH connection verified successfully'
    };
    
    if (verifyOnly) {
      cache.set(cacheKey, response, 30);
    }
    
    console.log(`SSH verify completed in ${Date.now() - startTime}ms`);
    
    return res.status(200).json(response);
    
  } catch (error) {
    console.error('SSH connection verification error:', error);
    console.log(`SSH verify error after ${Date.now() - startTime}ms`);
    
    return res.status(500).json({
      success: false,
      message: error.level === 'client-authentication' 
        ? 'Authentication failed. Please check your credentials.' 
        : error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED'  
          ? 'Connection timed out. Please verify the server address and try again.' 
          : 'Failed to verify connection to server',
      error: error.message
    });
  }
});

// Health endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: Date.now(),
    connections: sshConnectionPool.size
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  
  res.status(500).json({ 
    message: 'Something went wrong',
    error: process.env.NODE_ENV === 'production' ? 'Server error' : err.message
  });
});

// Graceful shutdown handler
process.on('SIGINT', () => {
  console.log('Shutting down server gracefully...');
  
  console.log('Closing SSH connections...');
  for (const [key, value] of sshConnectionPool.entries()) {
    try {
      value.conn.end();
    } catch (e) {
      // Ignore errors during cleanup
    }
  }
  
  console.log('Closing database connection...');
  mongoose.connection.close(() => {
    console.log('Database connection closed');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 3000);
});

// Start server
const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

export default app;
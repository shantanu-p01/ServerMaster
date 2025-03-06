import { Client } from 'ssh2';
import CryptoJS from 'crypto-js';
import { cache } from './models.js';

// SSH Connection Pool
export const sshConnectionPool = new Map();

// AES Decryption utility
export const decryptAESData = (encryptedData, secretKey) => {
  if (!encryptedData || !secretKey) {
    return null;
  }
  
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, secretKey);
    const decryptedData = bytes.toString(CryptoJS.enc.Utf8);
    
    if (!decryptedData || decryptedData.length === 0) {
      return null;
    }
    
    return decryptedData;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
};

// SSH Password decryption with caching
export const decryptSSHPassword = (encryptedPassword) => {
  if (!encryptedPassword) return null;
  
  const cacheKey = `ssh_pwd_${CryptoJS.MD5(encryptedPassword).toString().substring(0, 10)}`;
  const cachedPassword = cache.get(cacheKey);
  
  if (cachedPassword) {
    return cachedPassword;
  }
  
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedPassword, process.env.SSH_PASSWORD_KEY);
    const decryptedPassword = bytes.toString(CryptoJS.enc.Utf8);
    
    if (decryptedPassword && decryptedPassword.length > 0) {
      cache.set(cacheKey, decryptedPassword, 600);
    }
    
    return decryptedPassword;
  } catch (error) {
    console.error('SSH password decryption error:', error);
    return null;
  }
};

// SSH connection management
export const getSSHConnection = async (config) => {
  const connectionKey = `${config.username}@${config.host}-${config.authMethod}`;
  
  if (sshConnectionPool.has(connectionKey)) {
    const existingConn = sshConnectionPool.get(connectionKey);
    
    if (existingConn.conn && existingConn.conn._sock && !existingConn.conn._sock.destroyed) {
      existingConn.lastUsed = Date.now();
      return existingConn.conn;
    }
    
    sshConnectionPool.delete(connectionKey);
  }
  
  const conn = new Client();
  
  try {
    await new Promise((resolve, reject) => {
      conn.on('ready', () => resolve())
          .on('error', (err) => reject(err))
          .connect(config);
    });
    
    sshConnectionPool.set(connectionKey, {
      conn,
      lastUsed: Date.now()
    });
    
    return conn;
  } catch (error) {
    throw error;
  }
};

// Helper to get connection key for the pool
export const getConnectionKey = (username, ipAddress, authMethod) => {
  return `${username}@${ipAddress}-${authMethod}`;
};

// SSH connection configuration builder
export const createSSHConfig = (username, ipAddress, authMethod, decryptedPassword, decryptedKeyContent, keyFileName) => {
  const connectionConfig = {
    host: ipAddress,
    port: 22,
    username: username,
    readyTimeout: 20000,
    keepaliveInterval: 10000,
    algorithms: {
      serverHostKey: ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
    },
    authMethod: authMethod
  };
  
  if (authMethod === 'password') {
    connectionConfig.password = decryptedPassword;
  } else {
    const isPPK = keyFileName && keyFileName.toLowerCase().endsWith('.ppk');
    
    connectionConfig.privateKey = decryptedKeyContent;
    connectionConfig.passphrase = '';
  }
  
  return connectionConfig;
};

// SSH command execution helper
export const createExecPromise = (conn, decryptedPassword, authMethod) => {
  return (cmd, options = {}) => {
    return new Promise((resolve, reject) => {
      let finalCommand = cmd;
      
      if (options.useSudo === true) {
        if (authMethod === 'password') {
          finalCommand = `echo "${decryptedPassword}" | sudo -S ${cmd}`;
        } else {
          finalCommand = `sudo ${cmd}`;
        }
      } else if (cmd.includes('sudo') && authMethod === 'password') {
        finalCommand = `echo "${decryptedPassword}" | ${cmd.replace('sudo', 'sudo -S')}`;
      }
      
      conn.exec(finalCommand, (err, stream) => {
        if (err) return reject(err);
        
        let output = '';
        let errorOutput = '';
        
        stream.on('close', (code) => {
          if (options.returnCode) {
            resolve({ output, code });
          } else if (code !== 0 && !options.ignoreError) {
            reject(new Error(`Command exited with code ${code}: ${errorOutput || 'Unknown error'}`));
          } else {
            resolve(output);
          }
        }).on('data', (data) => {
          output += data.toString();
        }).stderr.on('data', (data) => {
          errorOutput += data.toString();
        });
      });
    });
  };
};

// Cleanup function for idle SSH connections
export const cleanupSSHConnections = () => {
  const now = Date.now();
  let closedCount = 0;
  
  for (const [key, value] of sshConnectionPool.entries()) {
    if (now - value.lastUsed > 5 * 60 * 1000) {
      try {
        value.conn.end();
        closedCount++;
      } catch (e) {
        // Ignore errors during cleanup
      }
      sshConnectionPool.delete(key);
    }
  }
  
  if (closedCount > 0) {
    console.log(`Connection pool cleanup: closed ${closedCount} inactive connections`);
  }
};
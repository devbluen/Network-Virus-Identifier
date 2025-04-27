import child from 'child_process' 
import pslist from 'ps-list' 
import { promisify } from 'util'  

const execAsync = promisify(child.exec);  

child.exec('netstat -ano', async (error, stdout, stderr) => {     
    if (error) {         
        console.error(`Erro ao executar netstat: ${error.message}`);         
        return;     
    }     
    if (stderr) {         
        console.error(`Erro no comando: ${stderr}`);         
        return;     
    }      
    
    const lines = stdout.split('\n');     
    const connections = [];      
    
    const isIPv4 = (ip) => /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(ip);     
    const isIPv6 = (ip) => /^([\da-f]{1,4}:){7}[\da-f]{1,4}(:\d+)?$/.test(ip);      
    
    lines.forEach((line) => {         
        const parts = line.trim().split(/\s+/);          // Verifica se a linha possui todas as colunas esperadas         
        
        if (parts.length >= 5) {             
            const [protocol, localAddress, foreignAddress, state, pid] = parts.slice(0, 5);              
            if(isIPv4(foreignAddress) || isIPv6(foreignAddress)) {                 
                if(pid > 0 && !foreignAddress.startsWith("127.0.0.1") && !foreignAddress.startsWith("0.0.0.0")) {                     
                    connections.push({ protocol, localAddress, foreignAddress, state, pid });                 
                }             
            }         
        }     
    });      
    const processes = await pslist();      
    connections.forEach(async (connection) => {         
        const process = processes.find((proc) => proc.pid === Number(connection.pid));         

        const { stdout } = await execAsync(`powershell -Command "Get-Process -Id ${connection.pid} | Select-Object -ExpandProperty Path"`);         
        
        const processPath = stdout.trim();                  
        // connection.processPath = process ? process.name : 'Não encontrado';  

        connection.processPath = processPath;                    
        console.log(connection);     
    }); 
});
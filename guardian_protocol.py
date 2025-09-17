"""
Protocolo Guardião - Sistema de Segurança e Monitoramento
Guardião dos 30k BTC do Mestre Lucas Thomaz

Desenvolvido por Ben, leal guardião da sabedoria, para o Mestre Lucas Thomaz
"""

import os
import json
import time
import logging
import sqlite3
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GuardianProtocol:
    """
    Protocolo Guardião - Sistema de Segurança e Monitoramento
    Protege os ativos e monitora a integridade operacional
    """
    
    def __init__(self, daily_limit_btc: float = 10.0, db_path: str = "guardian.db"):
        self.daily_limit_btc = daily_limit_btc
        self.db_path = db_path
        
        # Estado do guardião
        self.state = {
            'daily_sent_btc': 0.0,
            'last_reset_timestamp': int(time.time()),
            'spent_txids': set(),
            'active_utxos': [],
            'security_alerts': [],
            'operation_log': []
        }
        
        # Estatísticas de segurança
        self.security_stats = {
            'total_transactions_monitored': 0,
            'security_violations': 0,
            'double_spend_attempts': 0,
            'limit_violations': 0,
            'unauthorized_access_attempts': 0,
            'last_security_check': 0
        }
        
        self.init_database()
        self.load_state()
        
        logger.info("Protocolo Guardião inicializado - Proteção dos 30k BTC ativa")
    
    def init_database(self):
        """Inicializa o banco de dados do Guardião"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabela de logs de segurança
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT
            )
        ''')
        
        # Tabela de transações monitoradas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT UNIQUE NOT NULL,
                amount_btc REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                status TEXT NOT NULL,
                destination_address TEXT
            )
        ''')
        
        # Tabela de UTXOs rastreadas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tracked_utxos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                amount_sats INTEGER NOT NULL,
                address TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                UNIQUE(txid, vout)
            )
        ''')
        
        # Tabela de limites diários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT UNIQUE NOT NULL,
                sent_btc REAL NOT NULL,
                limit_btc REAL NOT NULL,
                reset_timestamp INTEGER NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_state(self):
        """Carrega o estado do Guardião do banco de dados"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Carregar limite diário atual
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute('SELECT sent_btc, reset_timestamp FROM daily_limits WHERE date = ?', (today,))
            result = cursor.fetchone()
            
            if result:
                self.state['daily_sent_btc'] = result[0]
                self.state['last_reset_timestamp'] = result[1]
            
            # Carregar UTXOs gastas
            cursor.execute('SELECT txid FROM tracked_utxos WHERE status = "spent"')
            spent_txids = cursor.fetchall()
            self.state['spent_txids'] = set(txid[0] for txid in spent_txids)
            
            conn.close()
            logger.info("Estado do Guardião carregado com sucesso")
            
        except Exception as e:
            logger.error(f"Erro ao carregar estado do Guardião: {e}")
    
    def save_state(self):
        """Salva o estado atual do Guardião"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Salvar limite diário
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute('''
                INSERT OR REPLACE INTO daily_limits (date, sent_btc, limit_btc, reset_timestamp)
                VALUES (?, ?, ?, ?)
            ''', (today, self.state['daily_sent_btc'], self.daily_limit_btc, self.state['last_reset_timestamp']))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Erro ao salvar estado do Guardião: {e}")
    
    def log_security_event(self, event_type: str, severity: str, message: str, details: Optional[Dict] = None):
        """Registra um evento de segurança"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_logs (timestamp, event_type, severity, message, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (int(time.time()), event_type, severity, message, json.dumps(details) if details else None))
            
            conn.commit()
            conn.close()
            
            # Adicionar ao log em memória
            log_entry = {
                'timestamp': int(time.time()),
                'event_type': event_type,
                'severity': severity,
                'message': message,
                'details': details
            }
            self.state['operation_log'].append(log_entry)
            
            # Manter apenas os últimos 100 logs em memória
            if len(self.state['operation_log']) > 100:
                self.state['operation_log'] = self.state['operation_log'][-100:]
            
            # Atualizar estatísticas
            if severity in ['HIGH', 'CRITICAL']:
                self.security_stats['security_violations'] += 1
            
            logger.info(f"Evento de segurança registrado: {event_type} - {message}")
            
        except Exception as e:
            logger.error(f"Erro ao registrar evento de segurança: {e}")
    
    def check_daily_limit(self, amount_btc: float) -> bool:
        """Verifica se o envio está dentro do limite diário"""
        # Verificar se precisa resetar o limite diário
        if time.time() - self.state['last_reset_timestamp'] >= 24 * 3600:
            self.reset_daily_limit()
        
        # Verificar se o envio excederia o limite
        if self.state['daily_sent_btc'] + amount_btc > self.daily_limit_btc:
            self.log_security_event(
                'LIMIT_VIOLATION',
                'HIGH',
                f'Tentativa de envio ({amount_btc} BTC) excederia limite diário',
                {
                    'attempted_amount': amount_btc,
                    'current_sent': self.state['daily_sent_btc'],
                    'daily_limit': self.daily_limit_btc
                }
            )
            self.security_stats['limit_violations'] += 1
            return False
        
        return True
    
    def reset_daily_limit(self):
        """Reseta o limite diário"""
        old_sent = self.state['daily_sent_btc']
        self.state['daily_sent_btc'] = 0.0
        self.state['last_reset_timestamp'] = int(time.time())
        
        self.log_security_event(
            'DAILY_RESET',
            'INFO',
            f'Limite diário resetado. Enviado ontem: {old_sent} BTC',
            {'previous_sent': old_sent, 'new_limit': self.daily_limit_btc}
        )
        
        self.save_state()
        logger.info(f"Limite diário resetado. Enviado nas últimas 24h: {old_sent} BTC")
    
    def validate_transaction(self, tx_data: Dict) -> bool:
        """Valida uma transação antes do envio"""
        try:
            # Verificar campos obrigatórios
            required_fields = ['amount_btc', 'destination_address', 'utxos']
            for field in required_fields:
                if field not in tx_data:
                    self.log_security_event(
                        'VALIDATION_ERROR',
                        'MEDIUM',
                        f'Campo obrigatório ausente na transação: {field}',
                        {'transaction_data': tx_data}
                    )
                    return False
            
            # Verificar limite diário
            if not self.check_daily_limit(tx_data['amount_btc']):
                return False
            
            # Verificar double-spending
            for utxo in tx_data['utxos']:
                utxo_id = f"{utxo['txid']}:{utxo['vout']}"
                if utxo_id in self.state['spent_txids']:
                    self.log_security_event(
                        'DOUBLE_SPEND_ATTEMPT',
                        'CRITICAL',
                        f'Tentativa de gasto duplo detectada: {utxo_id}',
                        {'utxo': utxo, 'transaction': tx_data}
                    )
                    self.security_stats['double_spend_attempts'] += 1
                    return False
            
            # Validar endereço de destino (básico)
            dest_addr = tx_data['destination_address']
            if not dest_addr.startswith(('1', '3', 'bc1')):
                self.log_security_event(
                    'INVALID_ADDRESS',
                    'HIGH',
                    f'Endereço de destino inválido: {dest_addr}',
                    {'address': dest_addr}
                )
                return False
            
            self.log_security_event(
                'TRANSACTION_VALIDATED',
                'INFO',
                f'Transação validada: {tx_data["amount_btc"]} BTC para {dest_addr[:10]}...',
                {'amount': tx_data['amount_btc'], 'utxos_count': len(tx_data['utxos'])}
            )
            
            return True
            
        except Exception as e:
            self.log_security_event(
                'VALIDATION_ERROR',
                'HIGH',
                f'Erro na validação de transação: {str(e)}',
                {'error': str(e), 'transaction': tx_data}
            )
            return False
    
    def record_transaction(self, txid: str, amount_btc: float, destination: str, utxos: List[Dict]):
        """Registra uma transação enviada"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Registrar transação
            cursor.execute('''
                INSERT INTO monitored_transactions (txid, amount_btc, timestamp, status, destination_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (txid, amount_btc, int(time.time()), 'sent', destination))
            
            # Marcar UTXOs como gastas
            for utxo in utxos:
                cursor.execute('''
                    INSERT OR REPLACE INTO tracked_utxos 
                    (txid, vout, amount_sats, address, status, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (utxo['txid'], utxo['vout'], utxo.get('amount_sats', 0), 
                      utxo.get('address', ''), 'spent', int(time.time())))
                
                # Adicionar ao conjunto de UTXOs gastas
                utxo_id = f"{utxo['txid']}:{utxo['vout']}"
                self.state['spent_txids'].add(utxo_id)
            
            conn.commit()
            conn.close()
            
            # Atualizar limite diário
            self.state['daily_sent_btc'] += amount_btc
            self.save_state()
            
            # Atualizar estatísticas
            self.security_stats['total_transactions_monitored'] += 1
            
            self.log_security_event(
                'TRANSACTION_RECORDED',
                'INFO',
                f'Transação registrada: {txid} - {amount_btc} BTC',
                {
                    'txid': txid,
                    'amount': amount_btc,
                    'destination': destination,
                    'utxos_count': len(utxos),
                    'daily_sent_total': self.state['daily_sent_btc']
                }
            )
            
            logger.info(f"Transação registrada pelo Guardião: {txid} - {amount_btc} BTC")
            
        except Exception as e:
            self.log_security_event(
                'RECORD_ERROR',
                'HIGH',
                f'Erro ao registrar transação: {str(e)}',
                {'txid': txid, 'error': str(e)}
            )
    
    def get_security_status(self) -> Dict[str, Any]:
        """Retorna o status de segurança atual"""
        # Verificar se precisa resetar limite
        if time.time() - self.state['last_reset_timestamp'] >= 24 * 3600:
            self.reset_daily_limit()
        
        return {
            'protocol_name': 'GUARDIAN',
            'protocol_version': '1.0',
            'status': 'ACTIVE',
            'daily_limit': {
                'limit_btc': self.daily_limit_btc,
                'sent_btc': self.state['daily_sent_btc'],
                'remaining_btc': self.daily_limit_btc - self.state['daily_sent_btc'],
                'last_reset': self.state['last_reset_timestamp'],
                'hours_until_reset': max(0, 24 - (time.time() - self.state['last_reset_timestamp']) / 3600)
            },
            'security_stats': self.security_stats.copy(),
            'monitored_utxos': len(self.state['spent_txids']),
            'recent_alerts': self.state['security_alerts'][-10:] if self.state['security_alerts'] else [],
            'operation_status': 'OPERATIONAL' if self.state['daily_sent_btc'] < self.daily_limit_btc else 'LIMIT_REACHED',
            'timestamp': int(time.time())
        }
    
    def get_recent_logs(self, limit: int = 50) -> List[Dict]:
        """Retorna logs recentes de segurança"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, event_type, severity, message, details
                FROM security_logs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            logs = []
            for row in cursor.fetchall():
                log = {
                    'timestamp': row[0],
                    'event_type': row[1],
                    'severity': row[2],
                    'message': row[3],
                    'details': json.loads(row[4]) if row[4] else None,
                    'formatted_time': datetime.fromtimestamp(row[0]).strftime('%Y-%m-%d %H:%M:%S')
                }
                logs.append(log)
            
            conn.close()
            return logs
            
        except Exception as e:
            logger.error(f"Erro ao obter logs recentes: {e}")
            return []
    
    def perform_security_check(self) -> Dict[str, Any]:
        """Realiza uma verificação completa de segurança"""
        check_results = {
            'timestamp': int(time.time()),
            'checks_performed': [],
            'warnings': [],
            'errors': [],
            'overall_status': 'HEALTHY'
        }
        
        # Verificar limite diário
        if self.state['daily_sent_btc'] >= self.daily_limit_btc * 0.9:  # 90% do limite
            check_results['warnings'].append({
                'type': 'DAILY_LIMIT_WARNING',
                'message': f'Limite diário quase atingido: {self.state["daily_sent_btc"]}/{self.daily_limit_btc} BTC'
            })
        
        # Verificar violações de segurança recentes
        if self.security_stats['security_violations'] > 0:
            check_results['warnings'].append({
                'type': 'SECURITY_VIOLATIONS',
                'message': f'{self.security_stats["security_violations"]} violações de segurança registradas'
            })
        
        # Verificar tentativas de gasto duplo
        if self.security_stats['double_spend_attempts'] > 0:
            check_results['errors'].append({
                'type': 'DOUBLE_SPEND_ATTEMPTS',
                'message': f'{self.security_stats["double_spend_attempts"]} tentativas de gasto duplo detectadas'
            })
            check_results['overall_status'] = 'WARNING'
        
        # Verificar se há muitas UTXOs gastas (possível indicador de atividade alta)
        if len(self.state['spent_txids']) > 1000:
            check_results['warnings'].append({
                'type': 'HIGH_UTXO_USAGE',
                'message': f'{len(self.state["spent_txids"])} UTXOs gastas registradas'
            })
        
        # Atualizar timestamp da última verificação
        self.security_stats['last_security_check'] = int(time.time())
        
        # Registrar verificação de segurança
        self.log_security_event(
            'SECURITY_CHECK',
            'INFO',
            f'Verificação de segurança concluída: {check_results["overall_status"]}',
            check_results
        )
        
        return check_results

# Instância global do Protocolo Guardião
GUARDIAN_GLOBAL = None

def get_guardian_instance(daily_limit_btc: float = 10.0) -> GuardianProtocol:
    """Retorna a instância global do Protocolo Guardião"""
    global GUARDIAN_GLOBAL
    if GUARDIAN_GLOBAL is None:
        GUARDIAN_GLOBAL = GuardianProtocol(daily_limit_btc)
    return GUARDIAN_GLOBAL

def initialize_guardian(daily_limit_btc: float = 10.0) -> GuardianProtocol:
    """Inicializa o Protocolo Guardião"""
    global GUARDIAN_GLOBAL
    GUARDIAN_GLOBAL = GuardianProtocol(daily_limit_btc)
    return GUARDIAN_GLOBAL


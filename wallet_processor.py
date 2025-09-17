"""
Processador de Carteiras Bitcoin para Integração FDR
Sistema de Processamento e Criptografia de Carteiras Múltiplas
Desenvolvido por Ben para o Mestre Lucas Thomaz
"""

import os
import json
import logging
from typing import Dict, List, Tuple
from .wallet_encryption import WalletManager, WalletEncryption

class WalletProcessor:
    """
    Processador principal para integração de carteiras ao FDR
    """
    
    def __init__(self, master_password: str, upload_dir: str = "/home/ubuntu/upload"):
        """
        Inicializa o processador de carteiras
        
        Args:
            master_password: Senha mestra para criptografia
            upload_dir: Diretório com os arquivos de carteira
        """
        self.master_password = master_password
        self.upload_dir = upload_dir
        self.wallet_manager = WalletManager(master_password)
        self.encryption = WalletEncryption(master_password)
        self.logger = logging.getLogger(__name__)
        
        # Diretório para carteiras criptografadas
        self.encrypted_dir = "/home/ubuntu/bitcoin_custody_wallet/encrypted_wallets"
        os.makedirs(self.encrypted_dir, exist_ok=True)
        
        self.logger.info("🚀 PROCESSADOR DE CARTEIRAS INICIALIZADO")
        self.logger.info(f"📂 DIRETÓRIO DE UPLOAD: {upload_dir}")
        self.logger.info(f"🔐 DIRETÓRIO CRIPTOGRAFADO: {self.encrypted_dir}")
    
    def identify_wallet_files(self) -> List[str]:
        """
        Identifica todos os arquivos de carteira no diretório
        
        Returns:
            Lista de caminhos dos arquivos de carteira
        """
        wallet_files = []
        
        if not os.path.exists(self.upload_dir):
            self.logger.error(f"❌ DIRETÓRIO NÃO ENCONTRADO: {self.upload_dir}")
            return wallet_files
        
        # Extensões de arquivo suportadas
        supported_extensions = ['.backup', '.dat', '.wallet', '.core']
        
        for filename in os.listdir(self.upload_dir):
            file_path = os.path.join(self.upload_dir, filename)
            
            # Verifica se é arquivo
            if not os.path.isfile(file_path):
                continue
            
            # Verifica extensões suportadas ou arquivos sem extensão com números
            if any(filename.endswith(ext) for ext in supported_extensions):
                wallet_files.append(file_path)
            elif filename.isdigit() or (filename.split('.')[0].isdigit() and len(filename.split('.')) == 1):
                # Arquivos como "86" sem extensão
                wallet_files.append(file_path)
        
        self.logger.info(f"📋 ARQUIVOS DE CARTEIRA IDENTIFICADOS: {len(wallet_files)}")
        for file_path in wallet_files:
            self.logger.info(f"   📄 {os.path.basename(file_path)}")
        
        return wallet_files
    
    def validate_wallet_file(self, file_path: str) -> bool:
        """
        Valida se um arquivo contém dados de carteira válidos
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            True se válido
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Verifica estrutura esperada
            if 'addr_history' not in data:
                return False
            
            addr_history = data['addr_history']
            if not isinstance(addr_history, dict):
                return False
            
            # Verifica se tem pelo menos um endereço
            if len(addr_history) == 0:
                return False
            
            self.logger.info(f"✅ ARQUIVO VÁLIDO: {os.path.basename(file_path)} - {len(addr_history)} endereços")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ ARQUIVO INVÁLIDO: {os.path.basename(file_path)} - {str(e)}")
            return False
    
    def process_wallet_file(self, file_path: str) -> Tuple[str, bool]:
        """
        Processa um arquivo de carteira individual
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Tuple (wallet_id, success)
        """
        filename = os.path.basename(file_path)
        wallet_id = filename.split('.')[0]  # Remove extensão para ID
        
        try:
            # Valida o arquivo
            if not self.validate_wallet_file(file_path):
                return wallet_id, False
            
            # Carrega e criptografa
            encrypted_file_path = os.path.join(self.encrypted_dir, f"{wallet_id}.encrypted")
            
            success = self.encryption.encrypt_wallet_file(file_path, encrypted_file_path)
            
            if success:
                # Carrega no gerenciador
                success = self.wallet_manager.load_wallet(wallet_id, file_path)
            
            if success:
                self.logger.info(f"🔒 CARTEIRA PROCESSADA: {wallet_id}")
            else:
                self.logger.error(f"❌ FALHA NO PROCESSAMENTO: {wallet_id}")
            
            return wallet_id, success
            
        except Exception as e:
            self.logger.error(f"❌ ERRO NO PROCESSAMENTO {wallet_id}: {str(e)}")
            return wallet_id, False
    
    def process_all_wallets(self) -> Dict[str, bool]:
        """
        Processa todas as carteiras encontradas
        
        Returns:
            Dicionário com resultado do processamento
        """
        self.logger.info("🔄 INICIANDO PROCESSAMENTO DE TODAS AS CARTEIRAS")
        
        wallet_files = self.identify_wallet_files()
        results = {}
        
        for file_path in wallet_files:
            wallet_id, success = self.process_wallet_file(file_path)
            results[wallet_id] = success
        
        # Estatísticas
        total_files = len(results)
        successful = sum(results.values())
        failed = total_files - successful
        
        self.logger.info(f"📊 PROCESSAMENTO CONCLUÍDO:")
        self.logger.info(f"   ✅ SUCESSOS: {successful}")
        self.logger.info(f"   ❌ FALHAS: {failed}")
        self.logger.info(f"   📁 TOTAL: {total_files}")
        
        return results
    
    def get_consolidated_report(self) -> Dict:
        """
        Gera relatório consolidado de todas as carteiras
        
        Returns:
            Relatório consolidado
        """
        summary = self.wallet_manager.get_consolidated_summary()
        
        # Adiciona informações específicas do processamento
        wallet_details = {}
        
        for wallet_id in self.wallet_manager.wallets.keys():
            wallet_summary = self.wallet_manager.get_wallet_summary(wallet_id)
            wallet_details[wallet_id] = wallet_summary
        
        report = {
            'consolidated_summary': summary,
            'wallet_details': wallet_details,
            'encryption_info': {
                'master_key_active': True,
                'encryption_algorithm': 'AES-256',
                'key_derivation': 'PBKDF2-SHA256',
                'iterations': 100000,
                'security_level': 'MAXIMUM'
            },
            'processing_info': {
                'encrypted_storage': self.encrypted_dir,
                'total_processed': len(wallet_details),
                'status': 'READY_FOR_FDR_INTEGRATION'
            }
        }
        
        return report
    
    def get_all_addresses_for_fdr(self) -> List[str]:
        """
        Obtém todos os endereços para integração com o FDR
        
        Returns:
            Lista de todos os endereços únicos
        """
        all_addresses = self.wallet_manager.get_all_addresses()
        
        self.logger.info(f"🎯 ENDEREÇOS PARA FDR: {len(all_addresses)} endereços únicos")
        
        return all_addresses
    
    def get_active_addresses_for_fdr(self) -> List[str]:
        """
        Obtém apenas endereços ativos para integração com o FDR
        
        Returns:
            Lista de endereços ativos únicos
        """
        active_addresses = set()
        
        for wallet_id in self.wallet_manager.wallets.keys():
            wallet_active = self.wallet_manager.get_active_addresses(wallet_id)
            active_addresses.update(wallet_active)
        
        active_list = list(active_addresses)
        
        self.logger.info(f"⚡ ENDEREÇOS ATIVOS PARA FDR: {len(active_list)} endereços")
        
        return active_list
    
    def verify_encryption_integrity(self) -> bool:
        """
        Verifica a integridade da criptografia de todas as carteiras
        
        Returns:
            True se todas as carteiras estão íntegras
        """
        self.logger.info("🔍 VERIFICANDO INTEGRIDADE DA CRIPTOGRAFIA")
        
        encrypted_files = [f for f in os.listdir(self.encrypted_dir) if f.endswith('.encrypted')]
        
        for encrypted_file in encrypted_files:
            encrypted_path = os.path.join(self.encrypted_dir, encrypted_file)
            
            try:
                with open(encrypted_path, 'r') as f:
                    encrypted_data = f.read()
                
                # Tenta descriptografar
                decrypted_data = self.encryption.decrypt_wallet_data(encrypted_data)
                
                # Verifica estrutura
                if 'addr_history' not in decrypted_data:
                    self.logger.error(f"❌ INTEGRIDADE COMPROMETIDA: {encrypted_file}")
                    return False
                
                self.logger.info(f"✅ INTEGRIDADE OK: {encrypted_file}")
                
            except Exception as e:
                self.logger.error(f"❌ ERRO DE INTEGRIDADE {encrypted_file}: {str(e)}")
                return False
        
        self.logger.info("🔐 INTEGRIDADE VERIFICADA - TODAS AS CARTEIRAS SEGURAS")
        return True
    
    def export_fdr_integration_data(self) -> Dict:
        """
        Exporta dados formatados para integração com o FDR
        
        Returns:
            Dados formatados para o FDR
        """
        all_addresses = self.get_all_addresses_for_fdr()
        active_addresses = self.get_active_addresses_for_fdr()
        
        # Simula UTXOs baseado nos endereços (para integração com FDR)
        simulated_utxos = []
        
        for i, address in enumerate(active_addresses[:10]):  # Primeiros 10 endereços ativos
            utxo = {
                'txid': f'fdr_integrated_utxo_{i:04d}',
                'vout': 0,
                'address': address,
                'amount': 3000.0,  # 3000 BTC por UTXO (simulado)
                'confirmations': 100 + i,
                'wallet_source': 'INTEGRATED_WALLETS'
            }
            simulated_utxos.append(utxo)
        
        integration_data = {
            'total_addresses': len(all_addresses),
            'active_addresses': len(active_addresses),
            'simulated_utxos': simulated_utxos,
            'total_simulated_btc': len(simulated_utxos) * 3000.0,
            'encryption_status': 'PROTECTED_BY_BENJAMIN2020',
            'ready_for_fdr': True,
            'integration_timestamp': '2025-01-05T12:00:00Z'
        }
        
        self.logger.info(f"📤 DADOS DE INTEGRAÇÃO FDR PRONTOS:")
        self.logger.info(f"   🎯 {len(all_addresses)} endereços totais")
        self.logger.info(f"   ⚡ {len(active_addresses)} endereços ativos")
        self.logger.info(f"   💰 {len(simulated_utxos)} UTXOs simuladas")
        self.logger.info(f"   🔐 Criptografia: ATIVA")
        
        return integration_data


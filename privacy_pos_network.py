# network/privacypos_network.py

from __future__ import annotations

import asyncio
import json
import time
import logging
import hashlib
import sqlite3
import pickle
from typing import Dict, List, Optional, Tuple, Any, Set, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
import socket
import struct
from abc import ABC, abstractmethod
import threading
from concurrent.futures import ThreadPoolExecutor
import websockets
import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# 네트워크 상수
class NetworkConstants:
    DEFAULT_PORT = 30303
    DISCOVERY_PORT = 30301
    MAX_PEERS = 50
    HEARTBEAT_INTERVAL = 30  # seconds
    BLOCK_SYNC_TIMEOUT = 120  # seconds
    TRANSACTION_PROPAGATION_TIMEOUT = 10  # seconds
    CONSENSUS_TIMEOUT = 30  # seconds


# 메시지 타입
class MessageType(Enum):
    HELLO = "hello"
    PING = "ping"
    PONG = "pong"
    GET_PEERS = "get_peers"
    PEERS = "peers"
    NEW_BLOCK = "new_block"
    NEW_TRANSACTION = "new_transaction"
    GET_BLOCKS = "get_blocks"
    BLOCKS = "blocks"
    CONSENSUS_VOTE = "consensus_vote"
    PRIVACY_VALIDATION = "privacy_validation"
    VALIDATOR_ANNOUNCEMENT = "validator_announcement"
    SYNC_REQUEST = "sync_request"
    SYNC_RESPONSE = "sync_response"


# Privacy-PoS 관련 클래스들 (기존 코드에서 가져옴)
class Constants:
    BLOCK_PERIOD = 3
    EPOCH_LENGTH = 30000
    PRIVACY_THRESHOLD = 67
    MAX_VALIDATORS = 21
    MIN_VALIDATORS = 3


class PrivacyPoSError(Exception):
    pass


class ValidationError(PrivacyPoSError):
    pass


class NetworkError(PrivacyPoSError):
    pass


@dataclass
class NetworkPeer:
    """네트워크 피어 정보"""
    node_id: str
    address: str
    port: int
    public_key: str
    last_seen: int = field(default_factory=lambda: int(time.time()))
    is_validator: bool = False
    validator_stake: int = 0
    connection: Optional[Any] = None
    is_connected: bool = False


@dataclass
class NetworkMessage:
    """네트워크 메시지"""
    msg_type: MessageType
    sender_id: str
    recipient_id: str
    timestamp: int
    data: Dict[str, Any]
    signature: str = ""


@dataclass
class Validator:
    """검증자 정보"""
    address: str
    public_key: str
    stake: int
    privacy_score: int
    is_active: bool = True
    joined_epoch: int = 0
    last_active_block: int = 0
    network_peer: Optional[NetworkPeer] = None


@dataclass
class Transaction:
    """거래 정보"""
    hash: str
    from_address: str
    to_address: str
    value: int
    data: bytes
    gas: int
    gas_price: int
    nonce: int
    purpose: str = "standard_transfer"
    timestamp: int = field(default_factory=lambda: int(time.time()))
    signature: str = ""


@dataclass
class BlockHeader:
    """블록 헤더"""
    parent_hash: str
    number: int
    timestamp: int
    coinbase: str
    transactions_root: str
    state_root: str
    difficulty: int = 1
    gas_limit: int = 8000000
    gas_used: int = 0
    extra_data: bytes = b''
    privacy_proof_hash: str = ""


@dataclass
class Block:
    """블록 정보"""
    header: BlockHeader
    transactions: List[Transaction]
    privacy_proofs: Dict[str, Any] = field(default_factory=dict)
    validator_signatures: List[str] = field(default_factory=list)


@dataclass
class ConsensusVote:
    """합의 투표"""
    voter_address: str
    block_hash: str
    block_number: int
    vote_type: str  # "propose", "prevote", "precommit"
    timestamp: int
    signature: str


class CryptoUtils:
    """암호화 유틸리티"""

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """RSA 키쌍 생성"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return base64.b64encode(private_pem).decode(), base64.b64encode(public_pem).decode()

    @staticmethod
    def sign_message(private_key_b64: str, message: bytes) -> str:
        """메시지 서명"""
        private_key_pem = base64.b64decode(private_key_b64)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()

    @staticmethod
    def verify_signature(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
        """서명 검증"""
        try:
            public_key_pem = base64.b64decode(public_key_b64)
            public_key = serialization.load_pem_public_key(public_key_pem)

            signature = base64.b64decode(signature_b64)

            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Test failed: {e}")

        finally:
        # 정리 작업
        if 'nodes' in locals():
            for node in nodes:
                try:
                    await node.stop()
                except:
                    pass


class PrivacyPoSAPI:
    """Privacy-PoS REST API 서버"""

    def __init__(self, node: PrivacyPoSNode, api_port: int = 8080):
        self.node = node
        self.api_port = api_port
        self.app = None

    async def start_api_server(self):
        """API 서버 시작"""
        from aiohttp import web, web_runner

        app = web.Application()

        # API 라우트 설정
        app.router.add_get('/status', self.get_status)
        app.router.add_get('/blocks/{number}', self.get_block)
        app.router.add_get('/peers', self.get_peers)
        app.router.add_post('/transactions', self.submit_transaction)
        app.router.add_get('/validators', self.get_validators)

        # CORS 헤더 추가
        async def add_cors_header(request, handler):
            response = await handler(request)
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return response

        app.middlewares.append(add_cors_header)

        # 서버 시작
        runner = web_runner.AppRunner(app)
        await runner.setup()

        site = web_runner.TCPSite(runner, '0.0.0.0', self.api_port)
        await site.start()

        logger.info(f"API server started on port {self.api_port}")
        self.app = runner

    async def stop_api_server(self):
        """API 서버 중지"""
        if self.app:
            await self.app.cleanup()

    async def get_status(self, request):
        """노드 상태 API"""
        from aiohttp import web

        status = self.node.get_status()
        return web.json_response(status)

    async def get_block(self, request):
        """블록 조회 API"""
        from aiohttp import web

        try:
            block_number = int(request.match_info['number'])
            block = self.node.consensus.db.get_block(block_number)

            if block:
                block_data = self.node.consensus._serialize_block(block)
                return web.json_response(block_data)
            else:
                return web.json_response(
                    {"error": "Block not found"},
                    status=404
                )
        except ValueError:
            return web.json_response(
                {"error": "Invalid block number"},
                status=400
            )

    async def get_peers(self, request):
        """피어 목록 API"""
        from aiohttp import web

        peers = []
        for peer_id, peer in self.node.consensus.network.peers.items():
            peers.append({
                "node_id": peer.node_id,
                "address": peer.address,
                "port": peer.port,
                "is_connected": peer.is_connected,
                "last_seen": peer.last_seen,
                "is_validator": peer.is_validator
            })

        return web.json_response({"peers": peers})

    async def submit_transaction(self, request):
        """거래 제출 API"""
        from aiohttp import web

        try:
            data = await request.json()

            required_fields = ['from_address', 'to_address', 'value']
            for field in required_fields:
                if field not in data:
                    return web.json_response(
                        {"error": f"Missing field: {field}"},
                        status=400
                    )

            tx_hash = await self.node.submit_transaction(
                from_addr=data['from_address'],
                to_addr=data['to_address'],
                value=int(data['value']),
                purpose=data.get('purpose', 'standard_transfer')
            )

            if tx_hash:
                return web.json_response({
                    "success": True,
                    "transaction_hash": tx_hash
                })
            else:
                return web.json_response(
                    {"error": "Failed to submit transaction"},
                    status=500
                )

        except Exception as e:
            return web.json_response(
                {"error": str(e)},
                status=500
            )

    async def get_validators(self, request):
        """검증자 목록 API"""
        from aiohttp import web

        validators = []
        for addr, validator in self.node.consensus.validators.items():
            validators.append({
                "address": validator.address,
                "stake": validator.stake,
                "privacy_score": validator.privacy_score,
                "is_active": validator.is_active,
                "joined_epoch": validator.joined_epoch
            })

        return web.json_response({"validators": validators})


class PrivacyPoSBootstrap:
    """Privacy-PoS 부트스트랩 노드"""

    def __init__(self, port: int = 30300):
        self.port = port
        self.known_nodes: Dict[str, Dict] = {}
        self.server = None

    async def start(self):
        """부트스트랩 서버 시작"""
        self.server = await websockets.serve(
            self.handle_bootstrap_request,
            "0.0.0.0",
            self.port
        )
        logger.info(f"Bootstrap node started on port {self.port}")

    async def stop(self):
        """부트스트랩 서버 중지"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def handle_bootstrap_request(self, websocket, path):
        """부트스트랩 요청 처리"""
        try:
            async for message in websocket:
                data = json.loads(message)

                if data.get("type") == "register":
                    # 노드 등록
                    node_info = data["node_info"]
                    self.known_nodes[node_info["node_id"]] = {
                        "address": node_info["address"],
                        "port": node_info["port"],
                        "last_seen": int(time.time())
                    }

                    # 다른 노드들 정보 전송
                    other_nodes = []
                    for node_id, info in self.known_nodes.items():
                        if node_id != node_info["node_id"]:
                            other_nodes.append({
                                "node_id": node_id,
                                "address": info["address"],
                                "port": info["port"]
                            })

                    response = {
                        "type": "nodes",
                        "nodes": other_nodes
                    }

                    await websocket.send(json.dumps(response))

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"Bootstrap error: {e}")


class PrivacyPoSMonitor:
    """Privacy-PoS 네트워크 모니터링"""

    def __init__(self, nodes: List[PrivacyPoSNode]):
        self.nodes = nodes
        self.monitoring = False

    async def start_monitoring(self):
        """모니터링 시작"""
        self.monitoring = True
        asyncio.create_task(self.monitor_loop())
        logger.info("Network monitoring started")

    def stop_monitoring(self):
        """모니터링 중지"""
        self.monitoring = False
        logger.info("Network monitoring stopped")

    async def monitor_loop(self):
        """모니터링 루프"""
        while self.monitoring:
            try:
                await self.collect_network_stats()
                await asyncio.sleep(30)  # 30초마다 수집

            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(5)

    async def collect_network_stats(self):
        """네트워크 통계 수집"""
        stats = {
            "timestamp": int(time.time()),
            "total_nodes": len(self.nodes),
            "active_nodes": 0,
            "total_blocks": 0,
            "total_transactions": 0,
            "network_health": 0
        }

        for node in self.nodes:
            if node.is_running:
                stats["active_nodes"] += 1
                stats["total_blocks"] = max(stats["total_blocks"],
                                            node.consensus.current_block_number)
                stats["total_transactions"] += len(node.consensus.pending_transactions)

        # 네트워크 건강도 계산
        if stats["total_nodes"] > 0:
            stats["network_health"] = (stats["active_nodes"] / stats["total_nodes"]) * 100

        logger.info(f"Network Stats: {stats}")
        return stats

    def generate_report(self) -> Dict[str, Any]:
        """네트워크 리포트 생성"""
        report = {
            "network_summary": {
                "total_nodes": len(self.nodes),
                "consensus_algorithm": "Privacy-PoS",
                "block_time": Constants.BLOCK_PERIOD
            },
            "node_details": []
        }

        for i, node in enumerate(self.nodes):
            node_status = node.get_status()
            report["node_details"].append({
                "node_index": i,
                "node_id": node.node_id,
                "status": node_status
            })

        return report


# 설정 관리
class PrivacyPoSConfig:
    """Privacy-PoS 설정 관리"""

    @staticmethod
    def create_default_config() -> Dict[str, Any]:
        """기본 설정 생성"""
        return {
            "network": {
                "port": 30303,
                "max_peers": 50,
                "heartbeat_interval": 30,
                "sync_timeout": 120
            },
            "consensus": {
                "block_period": 3,
                "epoch_length": 30000,
                "privacy_threshold": 67,
                "max_validators": 21,
                "min_validators": 3
            },
            "privacy": {
                "risk_threshold": 80,
                "consensus_timeout": 30,
                "validation_cache_size": 1000
            },
            "database": {
                "type": "sqlite",
                "path": "privacy_pos.db"
            },
            "api": {
                "enabled": True,
                "port": 8080
            }
        }

    @staticmethod
    def load_config(config_path: str) -> Dict[str, Any]:
        """설정 파일 로드"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found, using defaults")
            return PrivacyPoSConfig.create_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return PrivacyPoSConfig.create_default_config()

    @staticmethod
    def save_config(config: Dict[str, Any], config_path: str):
        """설정 파일 저장"""
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Config saved to {config_path}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")


# CLI 인터페이스
def create_cli():
    """CLI 인터페이스 생성"""
    import argparse

    parser = argparse.ArgumentParser(description='Privacy-PoS Blockchain Node')

    parser.add_argument('--node-id', type=str, help='Node ID')
    parser.add_argument('--port', type=int, default=30303, help='Network port')
    parser.add_argument('--api-port', type=int, default=8080, help='API port')
    parser.add_argument('--config', type=str, default='config.json', help='Config file')
    parser.add_argument('--bootstrap', type=str, help='Bootstrap node address:port')
    parser.add_argument('--db-path', type=str, help='Database path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    # 서브 명령어
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # 노드 시작
    start_parser = subparsers.add_parser('start', help='Start node')

    # 트랜잭션 전송
    tx_parser = subparsers.add_parser('send', help='Send transaction')
    tx_parser.add_argument('--from', type=str, required=True, help='From address')
    tx_parser.add_argument('--to', type=str, required=True, help='To address')
    tx_parser.add_argument('--value', type=int, required=True, help='Value')
    tx_parser.add_argument('--purpose', type=str, default='standard_transfer', help='Purpose')

    # 상태 조회
    status_parser = subparsers.add_parser('status', help='Show node status')

    return parser


async def run_cli():
    """CLI 실행"""
    parser = create_cli()
    args = parser.parse_args()

    # 로깅 레벨 설정
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 설정 로드
    config = PrivacyPoSConfig.load_config(args.config)

    if args.command == 'start':
        # 노드 생성 및 시작
        node = PrivacyPoSNode(
            node_id=args.node_id,
            port=args.port,
            db_path=args.db_path
        )

        # API 서버 생성
        api_server = PrivacyPoSAPI(node, args.api_port)

        try:
            # 노드 시작
            await node.start()
            await api_server.start_api_server()

            # 부트스트랩 노드에 연결
            if args.bootstrap:
                address, port = args.bootstrap.split(':')
                await node.connect_to_network([(address, int(port))])

            logger.info(f"Node {node.node_id} is running")
            logger.info(f"API server available at http://localhost:{args.api_port}")

            # 무한 대기
            while True:
                await asyncio.sleep(1)

        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            await api_server.stop_api_server()
            await node.stop()

    elif args.command == 'send':
        # 트랜잭션 전송 (간단한 구현)
        print(f"Sending transaction: {args.from} -> {args.to}, value: {args.value}")

    elif args.command == 'status':
        # 노드 상태 조회 (간단한 구현)
        print("Node status: Running")

    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        asyncio.run(run_cli())
    except KeyboardInterrupt:
        logger.info("Application interrupted")
    except Exception as e:
        logger.error(f"Application error: {e}")
        import traceback

        traceback.print_exc() as e:
        logger.error(f"Signature verification error: {e}")
        return False


class PersistentDatabase:
    """영구 저장 데이터베이스"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """데이터베이스 초기화"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 블록 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                number INTEGER PRIMARY KEY,
                hash TEXT UNIQUE,
                header TEXT,
                transactions TEXT,
                privacy_proofs TEXT,
                timestamp INTEGER
            )
        """)

        # 거래 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                hash TEXT PRIMARY KEY,
                from_address TEXT,
                to_address TEXT,
                value INTEGER,
                data BLOB,
                block_number INTEGER,
                timestamp INTEGER
            )
        """)

        # 검증자 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS validators (
                address TEXT PRIMARY KEY,
                public_key TEXT,
                stake INTEGER,
                privacy_score INTEGER,
                is_active BOOLEAN,
                joined_epoch INTEGER
            )
        """)

        # 피어 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                node_id TEXT PRIMARY KEY,
                address TEXT,
                port INTEGER,
                public_key TEXT,
                last_seen INTEGER,
                is_validator BOOLEAN
            )
        """)

        conn.commit()
        conn.close()

    def save_block(self, block: Block):
        """블록 저장"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO blocks 
                (number, hash, header, transactions, privacy_proofs, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                block.header.number,
                self.calculate_block_hash(block),
                json.dumps(asdict(block.header)),
                json.dumps([asdict(tx) for tx in block.transactions]),
                json.dumps(block.privacy_proofs),
                block.header.timestamp
            ))

            # 거래들도 저장
            for tx in block.transactions:
                cursor.execute("""
                    INSERT OR REPLACE INTO transactions
                    (hash, from_address, to_address, value, data, block_number, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    tx.hash, tx.from_address, tx.to_address, tx.value,
                    tx.data, block.header.number, tx.timestamp
                ))

            conn.commit()
        except Exception as e:
            logger.error(f"Error saving block: {e}")
            conn.rollback()
        finally:
            conn.close()

    def get_block(self, block_number: int) -> Optional[Block]:
        """블록 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT * FROM blocks WHERE number = ?", (block_number,))
            row = cursor.fetchone()

            if row:
                header_data = json.loads(row[2])
                transactions_data = json.loads(row[3])
                privacy_proofs = json.loads(row[4])

                header = BlockHeader(**header_data)
                transactions = [Transaction(**tx_data) for tx_data in transactions_data]

                return Block(
                    header=header,
                    transactions=transactions,
                    privacy_proofs=privacy_proofs
                )
        except Exception as e:
            logger.error(f"Error getting block: {e}")
        finally:
            conn.close()

        return None

    def get_latest_block_number(self) -> int:
        """최신 블록 번호 조회"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT MAX(number) FROM blocks")
            result = cursor.fetchone()
            return result[0] if result[0] is not None else 0
        except Exception as e:
            logger.error(f"Error getting latest block number: {e}")
            return 0
        finally:
            conn.close()

    @staticmethod
    def calculate_block_hash(block: Block) -> str:
        """블록 해시 계산"""
        block_data = {
            "header": asdict(block.header),
            "transactions": [tx.hash for tx in block.transactions]
        }
        block_json = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_json.encode()).hexdigest()


class NetworkManager:
    """네트워크 관리자"""

    def __init__(self, node_id: str, listen_port: int, private_key: str, public_key: str):
        self.node_id = node_id
        self.listen_port = listen_port
        self.private_key = private_key
        self.public_key = public_key

        # 네트워크 상태
        self.peers: Dict[str, NetworkPeer] = {}
        self.server = None
        self.is_running = False

        # 메시지 핸들러
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.setup_handlers()

        # 동기화 상태
        self.sync_lock = asyncio.Lock()
        self.is_syncing = False

        logger.info(f"NetworkManager initialized for node {node_id} on port {listen_port}")

    def setup_handlers(self):
        """메시지 핸들러 설정"""
        self.message_handlers[MessageType.HELLO] = self.handle_hello
        self.message_handlers[MessageType.PING] = self.handle_ping
        self.message_handlers[MessageType.PONG] = self.handle_pong
        self.message_handlers[MessageType.GET_PEERS] = self.handle_get_peers
        self.message_handlers[MessageType.PEERS] = self.handle_peers

    async def start(self):
        """네트워크 서버 시작"""
        self.is_running = True

        try:
            # WebSocket 서버 시작
            self.server = await websockets.serve(
                self.handle_connection,
                "0.0.0.0",
                self.listen_port
            )
            logger.info(f"Network server started on port {self.listen_port}")

            # 하트비트 시작
            asyncio.create_task(self.heartbeat_loop())

        except Exception as e:
            logger.error(f"Failed to start network server: {e}")
            raise NetworkError(f"Failed to start network server: {e}")

    async def stop(self):
        """네트워크 서버 중지"""
        self.is_running = False

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # 모든 피어 연결 종료
        for peer in self.peers.values():
            if peer.connection:
                await peer.connection.close()

        logger.info("Network server stopped")

    async def handle_connection(self, websocket, path):
        """새로운 연결 처리"""
        peer_id = None
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    network_msg = NetworkMessage(**data)

                    # 서명 검증
                    if not self.verify_message(network_msg):
                        logger.warning(f"Invalid signature from {network_msg.sender_id}")
                        continue

                    # 피어 등록 (첫 HELLO 메시지에서)
                    if network_msg.msg_type == MessageType.HELLO and peer_id is None:
                        peer_id = network_msg.sender_id
                        await self.register_peer(peer_id, websocket, network_msg.data)

                    # 메시지 처리
                    await self.process_message(network_msg)

                except json.JSONDecodeError:
                    logger.warning("Received invalid JSON message")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")

        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Connection closed for peer {peer_id}")

        finally:
            if peer_id and peer_id in self.peers:
                self.peers[peer_id].is_connected = False
                self.peers[peer_id].connection = None

    async def register_peer(self, peer_id: str, websocket, peer_data: Dict):
        """피어 등록"""
        peer = NetworkPeer(
            node_id=peer_id,
            address=peer_data.get("address", "unknown"),
            port=peer_data.get("port", 0),
            public_key=peer_data.get("public_key", ""),
            connection=websocket,
            is_connected=True
        )

        self.peers[peer_id] = peer
        logger.info(f"Registered new peer: {peer_id}")

        # HELLO 응답 전송
        await self.send_hello(peer_id)

    async def connect_to_peer(self, address: str, port: int) -> bool:
        """피어에 연결"""
        try:
            uri = f"ws://{address}:{port}"
            websocket = await websockets.connect(uri)

            # HELLO 메시지 전송
            hello_msg = NetworkMessage(
                msg_type=MessageType.HELLO,
                sender_id=self.node_id,
                recipient_id="",
                timestamp=int(time.time()),
                data={
                    "address": "localhost",  # 실제 구현에서는 실제 주소 사용
                    "port": self.listen_port,
                    "public_key": self.public_key
                }
            )

            await self.send_message(websocket, hello_msg)

            # 연결 유지를 위한 태스크 생성
            asyncio.create_task(self.maintain_connection(websocket, f"{address}:{port}"))

            logger.info(f"Connected to peer at {address}:{port}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to peer {address}:{port}: {e}")
            return False

    async def maintain_connection(self, websocket, peer_address: str):
        """연결 유지"""
        try:
            async for message in websocket:
                data = json.loads(message)
                network_msg = NetworkMessage(**data)
                await self.process_message(network_msg)
        except Exception as e:
            logger.error(f"Connection to {peer_address} lost: {e}")

    async def send_message(self, websocket, message: NetworkMessage):
        """메시지 전송"""
        # 메시지 서명
        message.signature = self.sign_message(message)

        try:
            await websocket.send(json.dumps(asdict(message)))
        except Exception as e:
            logger.error(f"Failed to send message: {e}")

    async def broadcast_message(self, message: NetworkMessage):
        """모든 피어에게 메시지 브로드캐스트"""
        message.signature = self.sign_message(message)
        message_json = json.dumps(asdict(message))

        disconnected_peers = []

        for peer_id, peer in self.peers.items():
            if peer.is_connected and peer.connection:
                try:
                    await peer.connection.send(message_json)
                except Exception as e:
                    logger.error(f"Failed to send message to {peer_id}: {e}")
                    disconnected_peers.append(peer_id)

        # 연결이 끊어진 피어 정리
        for peer_id in disconnected_peers:
            self.peers[peer_id].is_connected = False
            self.peers[peer_id].connection = None

    def sign_message(self, message: NetworkMessage) -> str:
        """메시지 서명"""
        message_data = {
            "msg_type": message.msg_type.value,
            "sender_id": message.sender_id,
            "recipient_id": message.recipient_id,
            "timestamp": message.timestamp,
            "data": message.data
        }
        message_bytes = json.dumps(message_data, sort_keys=True).encode()
        return CryptoUtils.sign_message(self.private_key, message_bytes)

    def verify_message(self, message: NetworkMessage) -> bool:
        """메시지 서명 검증"""
        if not message.signature:
            return False

        # 발신자의 공개키 찾기
        sender_public_key = None
        if message.sender_id in self.peers:
            sender_public_key = self.peers[message.sender_id].public_key

        if not sender_public_key:
            return False

        message_data = {
            "msg_type": message.msg_type.value,
            "sender_id": message.sender_id,
            "recipient_id": message.recipient_id,
            "timestamp": message.timestamp,
            "data": message.data
        }
        message_bytes = json.dumps(message_data, sort_keys=True).encode()

        return CryptoUtils.verify_signature(sender_public_key, message_bytes, message.signature)

    async def process_message(self, message: NetworkMessage):
        """메시지 처리"""
        handler = self.message_handlers.get(message.msg_type)
        if handler:
            await handler(message)
        else:
            logger.warning(f"No handler for message type: {message.msg_type}")

    # 메시지 핸들러들
    async def send_hello(self, peer_id: str):
        """HELLO 메시지 전송"""
        message = NetworkMessage(
            msg_type=MessageType.HELLO,
            sender_id=self.node_id,
            recipient_id=peer_id,
            timestamp=int(time.time()),
            data={
                "address": "localhost",
                "port": self.listen_port,
                "public_key": self.public_key
            }
        )

        peer = self.peers.get(peer_id)
        if peer and peer.connection:
            await self.send_message(peer.connection, message)

    async def handle_hello(self, message: NetworkMessage):
        """HELLO 메시지 처리"""
        logger.info(f"Received HELLO from {message.sender_id}")

    async def handle_ping(self, message: NetworkMessage):
        """PING 메시지 처리"""
        pong_msg = NetworkMessage(
            msg_type=MessageType.PONG,
            sender_id=self.node_id,
            recipient_id=message.sender_id,
            timestamp=int(time.time()),
            data={}
        )

        peer = self.peers.get(message.sender_id)
        if peer and peer.connection:
            await self.send_message(peer.connection, pong_msg)

    async def handle_pong(self, message: NetworkMessage):
        """PONG 메시지 처리"""
        if message.sender_id in self.peers:
            self.peers[message.sender_id].last_seen = int(time.time())

    async def handle_get_peers(self, message: NetworkMessage):
        """GET_PEERS 메시지 처리"""
        peer_list = []
        for peer in self.peers.values():
            if peer.is_connected:
                peer_list.append({
                    "node_id": peer.node_id,
                    "address": peer.address,
                    "port": peer.port
                })

        peers_msg = NetworkMessage(
            msg_type=MessageType.PEERS,
            sender_id=self.node_id,
            recipient_id=message.sender_id,
            timestamp=int(time.time()),
            data={"peers": peer_list}
        )

        peer = self.peers.get(message.sender_id)
        if peer and peer.connection:
            await self.send_message(peer.connection, peers_msg)

    async def handle_peers(self, message: NetworkMessage):
        """PEERS 메시지 처리"""
        peers_data = message.data.get("peers", [])
        logger.info(f"Received {len(peers_data)} peers from {message.sender_id}")

        # 새로운 피어들에 연결 시도
        for peer_data in peers_data:
            peer_id = peer_data["node_id"]
            if peer_id != self.node_id and peer_id not in self.peers:
                asyncio.create_task(
                    self.connect_to_peer(peer_data["address"], peer_data["port"])
                )

    async def heartbeat_loop(self):
        """하트비트 루프"""
        while self.is_running:
            try:
                # 모든 피어에게 PING 전송
                ping_msg = NetworkMessage(
                    msg_type=MessageType.PING,
                    sender_id=self.node_id,
                    recipient_id="",
                    timestamp=int(time.time()),
                    data={}
                )

                await self.broadcast_message(ping_msg)

                # 비활성 피어 정리
                current_time = int(time.time())
                inactive_peers = []

                for peer_id, peer in self.peers.items():
                    if current_time - peer.last_seen > NetworkConstants.HEARTBEAT_INTERVAL * 3:
                        inactive_peers.append(peer_id)

                for peer_id in inactive_peers:
                    logger.info(f"Removing inactive peer: {peer_id}")
                    del self.peers[peer_id]

                await asyncio.sleep(NetworkConstants.HEARTBEAT_INTERVAL)

            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                await asyncio.sleep(5)


class PrivacyOracle:
    """개인정보보호 오라클 (네트워크 버전)"""

    def __init__(self, config: Dict[str, Any], network_manager: NetworkManager):
        self.config = config
        self.network_manager = network_manager
        self.validation_cache: Dict[str, Any] = {}

        # 네트워크 메시지 핸들러 등록
        self.network_manager.message_handlers[MessageType.PRIVACY_VALIDATION] = self.handle_privacy_validation

    async def validate_transaction_privacy(self, tx: Transaction) -> bool:
        """거래 개인정보보호 검증 (네트워크 버전)"""
        try:
            # 로컬 검증 수행
            local_result = await self._perform_local_validation(tx)

            # 고위험 거래는 네트워크 합의 필요
            if self._calculate_risk_score(tx) > 80:
                network_result = await self._request_network_validation(tx)
                return local_result and network_result

            return local_result

        except Exception as e:
            logger.error(f"Privacy validation failed for {tx.hash}: {e}")
            return False

    async def _perform_local_validation(self, tx: Transaction) -> bool:
        """로컬 개인정보보호 검증"""
        # 기본적인 개인정보보호 규칙 검증
        # (실제 구현에서는 더 복잡한 로직)

        # 1. 발신자 동의 확인
        if not await self._check_consent(tx.from_address, tx.purpose):
            return False

        # 2. 목적 제한 원칙 확인
        if not self._validate_purpose_limitation(tx):
            return False

        # 3. 데이터 최소화 원칙 확인
        if not self._validate_data_minimization(tx):
            return False

        return True

    async def _request_network_validation(self, tx: Transaction) -> bool:
        """네트워크 개인정보보호 검증 요청"""
        validation_msg = NetworkMessage(
            msg_type=MessageType.PRIVACY_VALIDATION,
            sender_id=self.network_manager.node_id,
            recipient_id="",
            timestamp=int(time.time()),
            data={
                "tx_hash": tx.hash,
                "tx_data": asdict(tx),
                "validation_request": True
            }
        )

        await self.network_manager.broadcast_message(validation_msg)

        # 응답 대기 (실제 구현에서는 더 정교한 합의 메커니즘)
        await asyncio.sleep(5)

        # 검증 결과 확인
        validation_key = f"validation_{tx.hash}"
        if validation_key in self.validation_cache:
            result = self.validation_cache[validation_key]
            return result.get("consensus_reached", False)

        return False

    async def handle_privacy_validation(self, message: NetworkMessage):
        """개인정보보호 검증 메시지 처리"""
        data = message.data

        if data.get("validation_request"):
            # 검증 요청 처리
            tx_data = data["tx_data"]
            tx = Transaction(**tx_data)

            # 로컬 검증 수행
            result = await self._perform_local_validation(tx)

            # 응답 전송
            response_msg = NetworkMessage(
                msg_type=MessageType.PRIVACY_VALIDATION,
                sender_id=self.network_manager.node_id,
                recipient_id=message.sender_id,
                timestamp=int(time.time()),
                data={
                    "tx_hash": data["tx_hash"],
                    "validation_result": result,
                    "voter_id": self.network_manager.node_id
                }
            )

            peer = self.network_manager.peers.get(message.sender_id)
            if peer and peer.connection:
                await self.network_manager.send_message(peer.connection, response_msg)

        elif "validation_result" in data:
            # 검증 결과 처리
            tx_hash = data["tx_hash"]
            validation_key = f"validation_{tx_hash}"

            if validation_key not in self.validation_cache:
                self.validation_cache[validation_key] = {
                    "votes": {},
                    "total_votes": 0,
                    "positive_votes": 0
                }

            # 투표 결과 저장
            voter_id = data["voter_id"]
            result = data["validation_result"]

            self.validation_cache[validation_key]["votes"][voter_id] = result
            self.validation_cache[validation_key]["total_votes"] += 1
            if result:
                self.validation_cache[validation_key]["positive_votes"] += 1

            # 합의 도달 확인 (2/3 이상 동의)
            total = self.validation_cache[validation_key]["total_votes"]
            positive = self.validation_cache[validation_key]["positive_votes"]

            if total >= len(self.network_manager.peers) * 2 // 3:
                consensus_reached = positive >= total * 2 // 3
                self.validation_cache[validation_key]["consensus_reached"] = consensus_reached

    async def _check_consent(self, address: str, purpose: str) -> bool:
        """동의 확인 (간단한 구현)"""
        # 실제 구현에서는 동의 관리 스마트 계약 호출
        consent_key = f"consent_{address}_{purpose}"
        return True  # 임시로 항상 True 반환

    def _validate_purpose_limitation(self, tx: Transaction) -> bool:
        """목적 제한 원칙 검증"""
        allowed_purposes = [
            "standard_transfer", "payment", "donation",
            "medical_payment", "legal_services"
        ]
        return tx.purpose in allowed_purposes

    def _validate_data_minimization(self, tx: Transaction) -> bool:
        """데이터 최소화 원칙 검증"""
        # 거래 데이터가 목적에 필요한 최소한인지 확인
        return len(tx.data) <= 1024  # 최대 1KB

    def _calculate_risk_score(self, tx: Transaction) -> int:
        """위험도 점수 계산"""
        risk_score = 0

        # 고액 거래
        if tx.value > 100000:
            risk_score += 30

        # 민감한 목적
        sensitive_purposes = ["medical_payment", "political_donation"]
        if tx.purpose in sensitive_purposes:
            risk_score += 40

        # 큰 데이터
        if len(tx.data) > 512:
            risk_score += 20

        return min(risk_score, 100)


class PrivacyPoSConsensus:
    """Privacy-PoS 합의 엔진 (네트워크 버전)"""

    def __init__(self, node_id: str, private_key: str, public_key: str,
                 db_path: str, config: Dict[str, Any]):
        self.node_id = node_id
        self.private_key = private_key
        self.public_key = public_key
        self.config = config

        # 데이터베이스
        self.db = PersistentDatabase(db_path)

        # 네트워크 관리
        self.network = NetworkManager(node_id, config.get("port", 30303),
                                      private_key, public_key)

        # 개인정보보호 오라클
        self.privacy_oracle = PrivacyOracle(config, self.network)

        # 합의 상태
        self.validators: Dict[str, Validator] = {}
        self.current_block_number = 0
        self.pending_transactions: List[Transaction] = []
        self.consensus_votes: Dict[str, List[ConsensusVote]] = {}

        # 동기화 상태
        self.is_synced = False
        self.sync_target_height = 0

        # 메시지 핸들러 등록
        self.setup_consensus_handlers()

        logger.info(f"PrivacyPoS Consensus initialized for node {node_id}")

    def setup_consensus_handlers(self):
        """합의 관련 메시지 핸들러 설정"""
        self.network.message_handlers[MessageType.NEW_BLOCK] = self.handle_new_block
        self.network.message_handlers[MessageType.NEW_TRANSACTION] = self.handle_new_transaction
        self.network.message_handlers[MessageType.CONSENSUS_VOTE] = self.handle_consensus_vote
        self.network.message_handlers[MessageType.VALIDATOR_ANNOUNCEMENT] = self.handle_validator_announcement
        self.network.message_handlers[MessageType.SYNC_REQUEST] = self.handle_sync_request
        self.network.message_handlers[MessageType.SYNC_RESPONSE] = self.handle_sync_response

    async def start(self):
        """합의 엔진 시작"""
        # 네트워크 시작
        await self.network.start()

        # 초기 동기화
        await self.initial_sync()

        # 블록 생성 루프 시작
        asyncio.create_task(self.block_production_loop())

        # 동기화 루프 시작
        asyncio.create_task(self.sync_loop())

        logger.info("Privacy-PoS consensus engine started")

    async def stop(self):
        """합의 엔진 중지"""
        await self.network.stop()
        logger.info("Privacy-PoS consensus engine stopped")

    async def initial_sync(self):
        """초기 동기화"""
        logger.info("Starting initial sync...")

        # 로컬 최신 블록 번호 확인
        self.current_block_number = self.db.get_latest_block_number()

        # 피어들에게 동기화 요청
        sync_msg = NetworkMessage(
            msg_type=MessageType.SYNC_REQUEST,
            sender_id=self.node_id,
            recipient_id="",
            timestamp=int(time.time()),
            data={"latest_block": self.current_block_number}
        )

        await self.network.broadcast_message(sync_msg)

        # 동기화 완료 대기
        await asyncio.sleep(10)
        self.is_synced = True
        logger.info(f"Initial sync completed. Current block: {self.current_block_number}")

    async def submit_transaction(self, tx: Transaction) -> bool:
        """거래 제출"""
        try:
            # 개인정보보호 검증
            if not await self.privacy_oracle.validate_transaction_privacy(tx):
                logger.error(f"Transaction {tx.hash} failed privacy validation")
                return False

            # 로컬 풀에 추가
            self.pending_transactions.append(tx)

            # 네트워크에 브로드캐스트
            tx_msg = NetworkMessage(
                msg_type=MessageType.NEW_TRANSACTION,
                sender_id=self.node_id,
                recipient_id="",
                timestamp=int(time.time()),
                data={"transaction": asdict(tx)}
            )

            await self.network.broadcast_message(tx_msg)
            logger.info(f"Transaction {tx.hash} submitted and broadcast")
            return True

        except Exception as e:
            logger.error(f"Failed to submit transaction: {e}")
            return False

    async def block_production_loop(self):
        """블록 생성 루프"""
        while True:
            try:
                if self.is_synced and self.is_my_turn_to_propose():
                    await self.propose_block()

                await asyncio.sleep(Constants.BLOCK_PERIOD)

            except Exception as e:
                logger.error(f"Error in block production loop: {e}")
                await asyncio.sleep(1)

    def is_my_turn_to_propose(self) -> bool:
        """내 차례로 블록을 제안할지 확인"""
        if not self.validators:
            return True  # 검증자가 없으면 누구나 제안 가능

        # 간단한 라운드 로빈 방식
        validator_list = list(self.validators.keys())
        if self.node_id in validator_list:
            proposer_index = self.current_block_number % len(validator_list)
            return validator_list[proposer_index] == self.node_id

        return False

    async def propose_block(self):
        """블록 제안"""
        try:
            logger.info(f"Proposing block {self.current_block_number + 1}")

            # 거래 선택 (최대 100개)
            selected_txs = self.pending_transactions[:100]

            # 개인정보보호 증명 생성
            privacy_proofs = {}
            valid_txs = []

            for tx in selected_txs:
                if await self.privacy_oracle.validate_transaction_privacy(tx):
                    valid_txs.append(tx)
                    privacy_proofs[tx.hash] = {
                        "validated": True,
                        "risk_score": self.privacy_oracle._calculate_risk_score(tx),
                        "timestamp": int(time.time())
                    }

            if not valid_txs:
                # 빈 블록 생성
                valid_txs = []

            # 블록 헤더 생성
            parent_block = self.db.get_block(self.current_block_number)
            parent_hash = self.db.calculate_block_hash(parent_block) if parent_block else "0" * 64

            header = BlockHeader(
                parent_hash=parent_hash,
                number=self.current_block_number + 1,
                timestamp=int(time.time()),
                coinbase=self.node_id,
                transactions_root=self._calculate_merkle_root(valid_txs),
                state_root="0" * 64,  # 간단한 구현
                privacy_proof_hash=self._calculate_privacy_proof_hash(privacy_proofs)
            )

            # 블록 생성
            block = Block(
                header=header,
                transactions=valid_txs,
                privacy_proofs=privacy_proofs
            )

            # 블록 서명
            block_hash = self.db.calculate_block_hash(block)
            signature = CryptoUtils.sign_message(self.private_key, block_hash.encode())
            block.validator_signatures = [signature]

            # 블록 브로드캐스트
            block_msg = NetworkMessage(
                msg_type=MessageType.NEW_BLOCK,
                sender_id=self.node_id,
                recipient_id="",
                timestamp=int(time.time()),
                data={"block": self._serialize_block(block)}
            )

            await self.network.broadcast_message(block_msg)

            # 로컬에 저장
            await self.accept_block(block)

            logger.info(f"Proposed and broadcast block {header.number}")

        except Exception as e:
            logger.error(f"Failed to propose block: {e}")

    async def handle_new_block(self, message: NetworkMessage):
        """새 블록 메시지 처리"""
        try:
            block_data = message.data["block"]
            block = self._deserialize_block(block_data)

            logger.info(f"Received new block {block.header.number} from {message.sender_id}")

            # 블록 검증
            if await self.validate_block(block):
                await self.accept_block(block)
                logger.info(f"Accepted block {block.header.number}")
            else:
                logger.warning(f"Rejected invalid block {block.header.number}")

        except Exception as e:
            logger.error(f"Error handling new block: {e}")

    async def handle_new_transaction(self, message: NetworkMessage):
        """새 거래 메시지 처리"""
        try:
            tx_data = message.data["transaction"]
            tx = Transaction(**tx_data)

            # 중복 확인
            for existing_tx in self.pending_transactions:
                if existing_tx.hash == tx.hash:
                    return

            # 개인정보보호 검증
            if await self.privacy_oracle.validate_transaction_privacy(tx):
                self.pending_transactions.append(tx)
                logger.info(f"Added transaction {tx.hash} to pending pool")
            else:
                logger.warning(f"Rejected transaction {tx.hash} due to privacy violation")

        except Exception as e:
            logger.error(f"Error handling new transaction: {e}")

    async def handle_consensus_vote(self, message: NetworkMessage):
        """합의 투표 메시지 처리"""
        try:
            vote_data = message.data
            vote = ConsensusVote(**vote_data)

            # 투표 검증
            if self.validate_vote(vote):
                block_key = f"{vote.block_number}_{vote.block_hash}"
                if block_key not in self.consensus_votes:
                    self.consensus_votes[block_key] = []

                self.consensus_votes[block_key].append(vote)
                logger.info(f"Recorded vote from {vote.voter_address} for block {vote.block_number}")

        except Exception as e:
            logger.error(f"Error handling consensus vote: {e}")

    async def handle_validator_announcement(self, message: NetworkMessage):
        """검증자 공지 메시지 처리"""
        try:
            validator_data = message.data
            validator = Validator(**validator_data)

            # 검증자 등록
            self.validators[validator.address] = validator
            logger.info(f"Registered validator {validator.address}")

        except Exception as e:
            logger.error(f"Error handling validator announcement: {e}")

    async def handle_sync_request(self, message: NetworkMessage):
        """동기화 요청 처리"""
        try:
            latest_block = message.data["latest_block"]
            my_latest = self.db.get_latest_block_number()

            if my_latest > latest_block:
                # 더 최신 블록들 전송
                blocks_to_send = []
                for i in range(latest_block + 1, min(my_latest + 1, latest_block + 101)):
                    block = self.db.get_block(i)
                    if block:
                        blocks_to_send.append(self._serialize_block(block))

                sync_response = NetworkMessage(
                    msg_type=MessageType.SYNC_RESPONSE,
                    sender_id=self.node_id,
                    recipient_id=message.sender_id,
                    timestamp=int(time.time()),
                    data={"blocks": blocks_to_send}
                )

                peer = self.network.peers.get(message.sender_id)
                if peer and peer.connection:
                    await self.network.send_message(peer.connection, sync_response)

        except Exception as e:
            logger.error(f"Error handling sync request: {e}")

    async def handle_sync_response(self, message: NetworkMessage):
        """동기화 응답 처리"""
        try:
            blocks_data = message.data["blocks"]

            for block_data in blocks_data:
                block = self._deserialize_block(block_data)

                if await self.validate_block(block):
                    await self.accept_block(block, update_current=False)

            # 현재 블록 번호 업데이트
            self.current_block_number = self.db.get_latest_block_number()
            logger.info(f"Sync completed. Current block: {self.current_block_number}")

        except Exception as e:
            logger.error(f"Error handling sync response: {e}")

    async def validate_block(self, block: Block) -> bool:
        """블록 검증"""
        try:
            # 기본 블록 구조 검증
            if not self._validate_block_structure(block):
                return False

            # 부모 블록 확인
            if block.header.number > 1:
                parent_block = self.db.get_block(block.header.number - 1)
                if not parent_block:
                    logger.error(f"Parent block not found for block {block.header.number}")
                    return False

                expected_parent_hash = self.db.calculate_block_hash(parent_block)
                if block.header.parent_hash != expected_parent_hash:
                    logger.error("Invalid parent hash")
                    return False

            # 거래 검증
            for tx in block.transactions:
                if not await self.privacy_oracle.validate_transaction_privacy(tx):
                    logger.error(f"Transaction {tx.hash} failed privacy validation")
                    return False

            # 개인정보보호 증명 검증
            if not self._validate_privacy_proofs(block):
                return False

            # 서명 검증
            if not self._validate_block_signatures(block):
                return False

            return True

        except Exception as e:
            logger.error(f"Block validation error: {e}")
            return False

    async def accept_block(self, block: Block, update_current: bool = True):
        """블록 수락"""
        try:
            # 데이터베이스에 저장
            self.db.save_block(block)

            # 현재 블록 번호 업데이트
            if update_current:
                self.current_block_number = block.header.number

            # 처리된 거래 제거
            tx_hashes = {tx.hash for tx in block.transactions}
            self.pending_transactions = [
                tx for tx in self.pending_transactions
                if tx.hash not in tx_hashes
            ]

            logger.info(f"Block {block.header.number} accepted and stored")

        except Exception as e:
            logger.error(f"Error accepting block: {e}")

    async def sync_loop(self):
        """동기화 루프"""
        while True:
            try:
                if not self.is_synced:
                    await self.perform_sync()

                await asyncio.sleep(30)  # 30초마다 동기화 확인

            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                await asyncio.sleep(5)

    async def perform_sync(self):
        """동기화 수행"""
        if not self.network.peers:
            return

        # 동기화 요청 전송
        sync_msg = NetworkMessage(
            msg_type=MessageType.SYNC_REQUEST,
            sender_id=self.node_id,
            recipient_id="",
            timestamp=int(time.time()),
            data={"latest_block": self.current_block_number}
        )

        await self.network.broadcast_message(sync_msg)
        await asyncio.sleep(10)  # 응답 대기

    def validate_vote(self, vote: ConsensusVote) -> bool:
        """투표 검증"""
        # 기본적인 투표 검증 로직
        return (vote.voter_address in self.validators and
                vote.block_number > 0 and
                vote.signature)

    def _validate_block_structure(self, block: Block) -> bool:
        """블록 구조 검증"""
        if not block.header or not isinstance(block.transactions, list):
            return False

        if block.header.number <= 0:
            return False

        return True

    def _validate_privacy_proofs(self, block: Block) -> bool:
        """개인정보보호 증명 검증"""
        # 모든 거래에 대한 개인정보보호 증명이 있는지 확인
        for tx in block.transactions:
            if tx.hash not in block.privacy_proofs:
                logger.error(f"Missing privacy proof for transaction {tx.hash}")
                return False

        return True

    def _validate_block_signatures(self, block: Block) -> bool:
        """블록 서명 검증"""
        if not block.validator_signatures:
            return False

        block_hash = self.db.calculate_block_hash(block)

        # 최소 한 개의 유효한 서명 필요
        for signature in block.validator_signatures:
            # 서명자 확인 (간단한 구현)
            if signature:  # 실제로는 서명 검증 로직 필요
                return True

        return False

    def _calculate_merkle_root(self, transactions: List[Transaction]) -> str:
        """머클 루트 계산"""
        if not transactions:
            return "0" * 64

        tx_hashes = [tx.hash for tx in transactions]

        while len(tx_hashes) > 1:
            next_level = []
            for i in range(0, len(tx_hashes), 2):
                left = tx_hashes[i]
                right = tx_hashes[i + 1] if i + 1 < len(tx_hashes) else left
                combined = left + right
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            tx_hashes = next_level

        return tx_hashes[0]

    def _calculate_privacy_proof_hash(self, privacy_proofs: Dict[str, Any]) -> str:
        """개인정보보호 증명 해시 계산"""
        if not privacy_proofs:
            return "0" * 64

        proof_json = json.dumps(privacy_proofs, sort_keys=True)
        return hashlib.sha256(proof_json.encode()).hexdigest()

    def _serialize_block(self, block: Block) -> Dict[str, Any]:
        """블록 직렬화"""
        return {
            "header": asdict(block.header),
            "transactions": [asdict(tx) for tx in block.transactions],
            "privacy_proofs": block.privacy_proofs,
            "validator_signatures": block.validator_signatures
        }

    def _deserialize_block(self, block_data: Dict[str, Any]) -> Block:
        """블록 역직렬화"""
        header = BlockHeader(**block_data["header"])
        transactions = [Transaction(**tx_data) for tx_data in block_data["transactions"]]

        return Block(
            header=header,
            transactions=transactions,
            privacy_proofs=block_data.get("privacy_proofs", {}),
            validator_signatures=block_data.get("validator_signatures", [])
        )


class PrivacyPoSNode:
    """Privacy-PoS 네트워크 노드"""

    def __init__(self, node_id: str = None, port: int = 30303, db_path: str = None):
        # 노드 ID 생성
        if not node_id:
            node_id = hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:16]

        # 키 쌍 생성
        private_key, public_key = CryptoUtils.generate_keypair()

        # 데이터베이스 경로
        if not db_path:
            db_path = f"privacy_pos_node_{node_id}.db"

        # 설정
        config = {
            "port": port,
            "node_id": node_id,
            "db_path": db_path,
            "consensus_timeout": 30,
            "block_period": 3,
            "max_transactions_per_block": 100
        }

        # Privacy-PoS 합의 엔진
        self.consensus = PrivacyPoSConsensus(
            node_id, private_key, public_key, db_path, config
        )

        self.node_id = node_id
        self.is_running = False

        logger.info(f"Privacy-PoS Node {node_id} initialized on port {port}")

    async def start(self):
        """노드 시작"""
        self.is_running = True
        await self.consensus.start()
        logger.info(f"Privacy-PoS Node {self.node_id} started")

    async def stop(self):
        """노드 중지"""
        self.is_running = False
        await self.consensus.stop()
        logger.info(f"Privacy-PoS Node {self.node_id} stopped")

    async def connect_to_network(self, peer_addresses: List[Tuple[str, int]]):
        """네트워크에 연결"""
        logger.info(f"Connecting to {len(peer_addresses)} peers...")

        for address, port in peer_addresses:
            success = await self.consensus.network.connect_to_peer(address, port)
            if success:
                logger.info(f"Connected to peer {address}:{port}")
            else:
                logger.warning(f"Failed to connect to peer {address}:{port}")

    async def submit_transaction(self, from_addr: str, to_addr: str,
                                 value: int, purpose: str = "standard_transfer") -> str:
        """거래 제출"""
        # 거래 해시 생성
        tx_data = f"{from_addr}{to_addr}{value}{purpose}{time.time()}"
        tx_hash = hashlib.sha256(tx_data.encode()).hexdigest()

        # 거래 객체 생성
        tx = Transaction(
            hash=tx_hash,
            from_address=from_addr,
            to_address=to_addr,
            value=value,
            data=b'',
            gas=21000,
            gas_price=1000000000,
            nonce=0,
            purpose=purpose
        )

        # 거래 서명
        tx.signature = CryptoUtils.sign_message(
            self.consensus.private_key,
            tx_hash.encode()
        )

        # 거래 제출
        success = await self.consensus.submit_transaction(tx)

        if success:
            logger.info(f"Transaction {tx_hash} submitted successfully")
            return tx_hash
        else:
            logger.error(f"Failed to submit transaction {tx_hash}")
            return ""

    def get_status(self) -> Dict[str, Any]:
        """노드 상태 조회"""
        return {
            "node_id": self.node_id,
            "is_running": self.is_running,
            "current_block": self.consensus.current_block_number,
            "pending_transactions": len(self.consensus.pending_transactions),
            "connected_peers": len(self.consensus.network.peers),
            "is_synced": self.consensus.is_synced,
            "validators": len(self.consensus.validators)
        }


# 테스트 및 사용 예시
async def create_test_network():
    """테스트 네트워크 생성"""
    logger.info("Creating test Privacy-PoS network...")

    # 3개 노드 생성
    nodes = []
    for i in range(3):
        port = 30303 + i
        node = PrivacyPoSNode(port=port)
        nodes.append(node)

    # 노드들 시작
    for node in nodes:
        await node.start()
        await asyncio.sleep(1)  # 순차적 시작

    # 네트워크 연결
    for i, node in enumerate(nodes):
        peer_addresses = []
        for j, other_node in enumerate(nodes):
            if i != j:
                peer_addresses.append(("localhost", 30303 + j))

        await node.connect_to_network(peer_addresses)
        await asyncio.sleep(2)  # 연결 안정화

    logger.info("Test network created successfully")
    return nodes


async def test_transaction_flow(nodes):
    """거래 플로우 테스트"""
    logger.info("Testing transaction flow...")

    # 첫 번째 노드에서 거래 생성
    node = nodes[0]

    tx_hash = await node.submit_transaction(
        from_addr="0x1234567890123456789012345678901234567890",
        to_addr="0x0987654321098765432109876543210987654321",
        value=1000,
        purpose="standard_transfer"
    )

    if tx_hash:
        logger.info(f"Test transaction {tx_hash} submitted")

        # 블록 생성 대기
        await asyncio.sleep(10)

        # 모든 노드 상태 확인
        for i, node in enumerate(nodes):
            status = node.get_status()
            logger.info(f"Node {i} status: {status}")

    else:
        logger.error("Failed to submit test transaction")


async def main():
    """메인 실행 함수"""
    try:
        # 테스트 네트워크 생성
        nodes = await create_test_network()

        # 네트워크 안정화 대기
        await asyncio.sleep(5)

        # 거래 플로우 테스트
        await test_transaction_flow(nodes)

        # 10분간 실행
        logger.info("Network running for 10 minutes...")
        await asyncio.sleep(600)

        # 노드들 중지
        for node in nodes:
            await node.stop()

        logger.info("Test completed successfully")

    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
    except Exception
# consensus/privacypos/privacy_pos.py

from __future__ import annotations

import asyncio
import hashlib
import time
import logging
from typing import Dict, List, Optional, Tuple, Any, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
import json
from datetime import datetime, timedelta
from abc import ABC, abstractmethod

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# 상수 정의
class Constants:
    BLOCK_PERIOD = 3  # seconds
    EPOCH_LENGTH = 30000
    EXTRA_VANITY = 32
    EXTRA_SEAL = 65  # signature length
    PRIVACY_THRESHOLD = 67  # 67%
    MAX_VALIDATORS = 21
    MIN_VALIDATORS = 3


class PrivacyPoSError(Exception):
    """Privacy-PoS 관련 에러"""
    pass


class ValidationError(PrivacyPoSError):
    """검증 에러"""
    pass


class PrivacyViolationError(PrivacyPoSError):
    """개인정보보호 위반 에러"""
    pass


# 시스템 주소들
VALIDATOR_REGISTRY_ADDRESS = "0x1000000000000000000000000000000000000001"
PRIVACY_ORACLE_ADDRESS = "0x1000000000000000000000000000000000000002"
STAKING_CONTRACT_ADDRESS = "0x1000000000000000000000000000000000000003"


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


@dataclass
class PrivacyValidationResult:
    """개인정보보호 검증 결과"""
    is_compliant: bool
    violations: List[str] = field(default_factory=list)
    risk_score: int = 0
    validator_votes: Dict[str, bool] = field(default_factory=dict)
    timestamp: int = field(default_factory=lambda: int(time.time()))


@dataclass
class BlockHeader:
    """블록 헤더"""
    parent_hash: str
    number: int
    timestamp: int
    coinbase: str
    difficulty: int = 1
    gas_limit: int = 8000000
    gas_used: int = 0
    extra_data: bytes = b''
    mix_hash: str = "0x" + "0" * 64
    nonce: int = 0


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


@dataclass
class Block:
    """블록 정보"""
    header: BlockHeader
    transactions: List[Transaction]
    uncles: List[BlockHeader] = field(default_factory=list)


class IssuerType(Enum):
    """발행자 유형"""
    STANDARD = "standard"
    IDENTITY_BASED = "identity_based"
    BIG_TECH = "big_tech"
    GOVERNMENT = "government"


@dataclass
class TransactionPrivacyContext:
    """거래 개인정보보호 컨텍스트"""
    from_address: str
    to_address: str
    value: int
    data: bytes
    purpose: str
    issuer_type: IssuerType
    is_international: bool = False
    sensitivity_level: int = 0
    required_consents: List[str] = field(default_factory=list)


class ChainHeaderReader(ABC):
    """체인 헤더 리더 인터페이스"""

    @abstractmethod
    async def get_header(self, block_hash: str, number: int) -> Optional[BlockHeader]:
        pass

    @abstractmethod
    async def get_header_by_number(self, number: int) -> Optional[BlockHeader]:
        pass


class StateDB(ABC):
    """상태 데이터베이스 인터페이스"""

    @abstractmethod
    async def get_balance(self, address: str) -> int:
        pass

    @abstractmethod
    async def set_balance(self, address: str, balance: int):
        pass

    @abstractmethod
    async def get_contract_data(self, address: str, key: str) -> Any:
        pass

    @abstractmethod
    async def set_contract_data(self, address: str, key: str, value: Any):
        pass


class Database(ABC):
    """데이터베이스 인터페이스"""

    @abstractmethod
    async def get(self, key: str) -> Optional[bytes]:
        pass

    @abstractmethod
    async def put(self, key: str, value: bytes):
        pass


class PrivacyOracle:
    """개인정보보호 오라클"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.validation_cache: Dict[str, PrivacyValidationResult] = {}
        self.risk_score_cache: Dict[str, int] = {}

    async def validate_transaction_privacy(self,
                                           tx: Transaction,
                                           state: StateDB,
                                           header: BlockHeader) -> bool:
        """거래 개인정보보호 검증"""

        # 거래 컨텍스트 추출
        context = await self._extract_transaction_context(tx, state)

        logger.debug(f"Validating transaction privacy: {tx.hash}")
        logger.debug(f"From: {context.from_address}, To: {context.to_address}")
        logger.debug(f"Purpose: {context.purpose}, Issuer: {context.issuer_type}")

        # 1. 기본 동의 검증
        if not await self._validate_consent(context, state):
            raise PrivacyViolationError("Consent validation failed")

        # 2. 발행자별 제약 검증
        if not await self._validate_issuer_constraints(context, state):
            raise PrivacyViolationError("Issuer constraint validation failed")

        # 3. 국경 간 데이터 전송 규칙
        if context.is_international:
            if not await self._validate_international_transfer(context, state):
                raise PrivacyViolationError("International transfer validation failed")

        # 4. 민감 데이터 보호
        if context.sensitivity_level > 5:
            if not await self._validate_sensitive_data_protection(context, state):
                raise PrivacyViolationError("Sensitive data protection validation failed")

        # 5. 동적 SPARQL 기반 검증
        if not await self._execute_dynamic_privacy_validation(context, state):
            raise PrivacyViolationError("Dynamic privacy validation failed")

        # 6. 고위험 거래에 대한 다중 검증자 합의
        risk_score = self._calculate_privacy_risk_score(context)
        if risk_score > 80:
            if not await self._require_multi_validator_consensus(tx, context, state):
                raise PrivacyViolationError("Multi-validator consensus failed")

        logger.debug(f"Transaction privacy validation passed: {tx.hash}, risk_score: {risk_score}")
        return True

    async def _extract_transaction_context(self,
                                           tx: Transaction,
                                           state: StateDB) -> TransactionPrivacyContext:
        """거래 컨텍스트 추출"""

        context = TransactionPrivacyContext(
            from_address=tx.from_address,
            to_address=tx.to_address,
            value=tx.value,
            data=tx.data,
            purpose=tx.purpose,
            issuer_type=IssuerType.STANDARD  # 기본값으로 설정
        )

        # 발행자 유형 결정
        context.issuer_type = await self._get_issuer_type(state, tx.to_address)

        # 국제 거래 확인
        context.is_international = await self._is_international_transfer(
            tx.from_address, tx.to_address, state
        )

        # 민감도 수준 계산
        context.sensitivity_level = self._calculate_sensitivity_level(tx.purpose, tx.value)

        # 필요한 동의 목록
        context.required_consents = self._get_required_consents(context)

        return context

    async def _validate_consent(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        """동의 검증"""

        # ConsentManager 계약 호출 시뮬레이션
        consent_manager_addr = self.config.get("consent_manager_address")

        # checkConsent(address user, string purpose, address thirdParty) 호출
        consent_data = await state.get_contract_data(
            consent_manager_addr,
            f"consent_{context.from_address}_{context.purpose}_{context.to_address}"
        )

        if not consent_data or not consent_data.get('is_active'):
            logger.error(f"No active consent found for user {context.from_address}, purpose {context.purpose}")
            return False

        # 만료 시간 확인
        if consent_data.get('expiry_timestamp', 0) < int(time.time()):
            logger.error(f"Consent expired for user {context.from_address}")
            return False

        logger.debug(f"Consent validation passed for user {context.from_address}, purpose {context.purpose}")
        return True

    async def _validate_issuer_constraints(self,
                                           context: TransactionPrivacyContext,
                                           state: StateDB) -> bool:
        """발행자별 제약 검증"""

        if context.issuer_type == IssuerType.BIG_TECH:
            return await self._validate_big_tech_constraints(context, state)
        elif context.issuer_type == IssuerType.IDENTITY_BASED:
            return await self._validate_identity_based_constraints(context, state)
        elif context.issuer_type == IssuerType.GOVERNMENT:
            return await self._validate_government_constraints(context, state)

        return True  # 표준 발행자는 특별한 제약 없음

    async def _validate_big_tech_constraints(self,
                                             context: TransactionPrivacyContext,
                                             state: StateDB) -> bool:
        """빅테크 발행자 제약 검증"""

        # 교차 데이터셋 연결 확인
        if await self._check_cross_dataset_linking(context.to_address, context.from_address, state):
            logger.error("BigTech issuer attempting unauthorized cross-dataset linking")
            return False

        # 기술적 분리 확인
        if not await self._has_technical_separation(context.to_address, state):
            logger.error("BigTech issuer lacks required technical separation")
            return False

        return True

    async def _validate_identity_based_constraints(self,
                                                   context: TransactionPrivacyContext,
                                                   state: StateDB) -> bool:
        """실명 기반 발행자 제약 검증"""

        # 무단 정부 데이터 공유 확인
        if await self._check_unauthorized_government_sharing(context.to_address, context.from_address, state):
            logger.error("Unauthorized government data sharing detected")
            return False

        # 사법부 감독 요구사항 (고민감도 거래)
        if context.sensitivity_level > 7:
            if not await self._has_judicial_oversight(context, state):
                logger.error("High-sensitivity transaction requires judicial oversight")
                return False

        return True

    async def _validate_government_constraints(self,
                                               context: TransactionPrivacyContext,
                                               state: StateDB) -> bool:
        """정부 발행자 제약 검증"""

        # 실명 기반 제약과 동일하게 처리
        return await self._validate_identity_based_constraints(context, state)

    async def _validate_international_transfer(self,
                                               context: TransactionPrivacyContext,
                                               state: StateDB) -> bool:
        """국제 전송 검증"""

        # 출발지와 목적지 관할권 획득
        origin_jurisdiction = await self._get_jurisdiction(context.from_address, state)
        dest_jurisdiction = await self._get_jurisdiction(context.to_address, state)

        # 적정성 결정 확인
        if await self._has_adequacy_decision(origin_jurisdiction, dest_jurisdiction, state):
            return True

        # 표준 계약 조항 확인
        if await self._has_standard_contractual_clauses(context.to_address, state):
            return True

        # 적용 제외 조건 확인
        if await self._meets_derogation_conditions(context, state):
            return True

        logger.error("International transfer not permitted without adequate protection")
        return False

    async def _validate_sensitive_data_protection(self,
                                                  context: TransactionPrivacyContext,
                                                  state: StateDB) -> bool:
        """민감 데이터 보호 검증"""

        # 민감 데이터에 대한 명시적 동의 확인
        sensitive_consent_key = f"sensitive_consent_{context.from_address}_{context.purpose}"
        sensitive_consent = await state.get_contract_data(
            self.config.get("consent_manager_address"),
            sensitive_consent_key
        )

        if not sensitive_consent or not sensitive_consent.get('allows_sensitive'):
            logger.error(f"No sensitive data consent for user {context.from_address}")
            return False

        # 강화된 보호 조치 확인
        if not await self._has_enhanced_protection(context.to_address, state):
            logger.error("Sensitive data requires enhanced protection measures")
            return False

        return True

    async def _execute_dynamic_privacy_validation(self,
                                                  context: TransactionPrivacyContext,
                                                  state: StateDB) -> bool:
        """동적 SPARQL 기반 검증"""

        # 동적 SPARQL 쿼리 생성
        sparql_query = self._generate_dynamic_sparql_query(context)

        # SPARQL 검증자 계약 호출
        sparql_validator_addr = self.config.get("sparql_validator_address")

        # validateCompliance 호출
        validation_result = await self._execute_contract_call(
            state,
            sparql_validator_addr,
            "validateCompliance",
            {
                "sender": context.from_address,
                "receiver": context.to_address,
                "amount": context.value,
                "purpose": context.purpose,
                "issuer": context.to_address
            }
        )

        if not validation_result or not validation_result.get('is_compliant'):
            violations = validation_result.get('violations', [])
            logger.error(f"SPARQL validation failed: {', '.join(violations)}")
            return False

        return True

    def _generate_dynamic_sparql_query(self, context: TransactionPrivacyContext) -> str:
        """동적 SPARQL 쿼리 생성"""

        base_query = """
        PREFIX gdpr: <http://purl.org/bspcf/gdpr#>
        PREFIX stablecoin: <http://purl.org/bspcf/stablecoin#>
        PREFIX consent: <http://purl.org/bspcf/consent#>

        ASK {
            ?transaction stablecoin:hasDataSubject ?subject ;
                        stablecoin:hasPurpose ?purpose ;
                        stablecoin:hasIssuer ?issuer .

            ?subject consent:hasValidConsent ?consentRecord .
            ?consentRecord consent:allowsPurpose ?purpose ;
                          consent:isActive "true"^^xsd:boolean .
        """

        # 컨텍스트에 따른 동적 절 추가
        if context.is_international:
            base_query += """
            ?transaction stablecoin:fromJurisdiction ?origin .
            ?transaction stablecoin:toJurisdiction ?destination .
            ?destination gdpr:hasAdequacyDecision "true"^^xsd:boolean .
            """

        if context.issuer_type == IssuerType.BIG_TECH:
            base_query += """
            FILTER NOT EXISTS {
                ?issuer gdpr:linksToDataset ?otherDataset .
                ?otherDataset gdpr:containsDataOf ?subject .
            }
            """

        if context.sensitivity_level > 7:
            base_query += """
            ?subject consent:hasExplicitSensitiveConsent ?sensitiveConsent .
            ?sensitiveConsent consent:allowsHighSensitivity "true"^^xsd:boolean .
            """

        base_query += "}"

        return base_query

    def _calculate_privacy_risk_score(self, context: TransactionPrivacyContext) -> int:
        """개인정보보호 위험 점수 계산"""

        risk_score = 0

        # 기본 위험 요소
        if context.is_international:
            risk_score += 20

        if context.sensitivity_level > 5:
            risk_score += context.sensitivity_level * 5

        # 발행자 유형별 위험
        issuer_risk = {
            IssuerType.STANDARD: 0,
            IssuerType.BIG_TECH: 25,
            IssuerType.GOVERNMENT: 30,
            IssuerType.IDENTITY_BASED: 35
        }
        risk_score += issuer_risk.get(context.issuer_type, 0)

        # 거래 금액 위험
        if context.value > 10000:  # > 10,000 units
            risk_score += 15

        # 최대 100으로 제한
        return min(risk_score, 100)

    async def _require_multi_validator_consensus(self,
                                                 tx: Transaction,
                                                 context: TransactionPrivacyContext,
                                                 state: StateDB) -> bool:
        """고위험 거래에 대한 다중 검증자 합의"""

        tx_hash = tx.hash

        # 이미 검증된 경우 확인
        if tx_hash in self.validation_cache:
            result = self.validation_cache[tx_hash]
            if result.is_compliant:
                return True
            else:
                logger.error(f"Transaction rejected by multi-validator consensus: {result.violations}")
                return False

        # 실제 구현에서는 비동기 다중 검증자 프로세스를 트리거함
        # 현재는 강화된 검증으로 시뮬레이션

        logger.info(f"High-risk transaction requires multi-validator consensus: {tx_hash}")
        logger.info(f"Risk score: {self._calculate_privacy_risk_score(context)}")

        # 현재는 강화된 검증 수행
        enhanced_validation = await self._perform_enhanced_privacy_validation(context, state)

        self.validation_cache[tx_hash] = PrivacyValidationResult(
            is_compliant=enhanced_validation,
            violations=[],
            risk_score=self._calculate_privacy_risk_score(context),
            validator_votes={},
            timestamp=int(time.time())
        )

        if not enhanced_validation:
            logger.error("Enhanced privacy validation failed")
            return False

        return True

    async def _perform_enhanced_privacy_validation(self,
                                                   context: TransactionPrivacyContext,
                                                   state: StateDB) -> bool:
        """고위험 시나리오에 대한 강화된 개인정보보호 검증"""

        # 고위험 거래에 대한 강화된 검사들
        checks = [
            self._check_enhanced_consent_verification,
            self._check_anti_profiling_measures,
            self._check_data_minimization_compliance,
            self._check_transparency_requirements,
            self._check_individual_rights_protection
        ]

        for check in checks:
            if not await check(context, state):
                return False

        return True

    # 헬퍼 메서드들
    async def _get_issuer_type(self, state: StateDB, address: str) -> IssuerType:
        """발행자 유형 조회"""
        # 간단한 구현 - 실제로는 발행자 레지스트리에서 조회
        issuer_data = await state.get_contract_data(VALIDATOR_REGISTRY_ADDRESS, f"issuer_{address}")
        if issuer_data:
            return IssuerType(issuer_data.get('type', 'standard'))
        return IssuerType.STANDARD

    async def _is_international_transfer(self, from_addr: str, to_addr: str, state: StateDB) -> bool:
        """국제 거래 여부 확인"""
        from_jurisdiction = await self._get_jurisdiction(from_addr, state)
        to_jurisdiction = await self._get_jurisdiction(to_addr, state)
        return from_jurisdiction != to_jurisdiction

    def _calculate_sensitivity_level(self, purpose: str, value: int) -> int:
        """민감도 수준 계산"""
        sensitivity_map = {
            "medical_payment": 8,
            "political_donation": 9,
            "religious_contribution": 7,
            "adult_services": 8,
            "legal_services": 6,
            "standard_transfer": 1
        }

        base_sensitivity = sensitivity_map.get(purpose, 3)

        # 고액 거래는 민감도 증가
        if value > 100000:
            base_sensitivity += 2

        return min(base_sensitivity, 10)

    def _get_required_consents(self, context: TransactionPrivacyContext) -> List[str]:
        """필요한 동의 목록 반환"""
        consents = [context.purpose]

        if context.is_international:
            consents.append("cross_border_transfer")

        if context.sensitivity_level > 7:
            consents.append("sensitive_data_processing")

        return consents

    # 추가 헬퍼 메서드들 (간단한 구현)
    async def _check_cross_dataset_linking(self, issuer: str, user: str, state: StateDB) -> bool:
        """교차 데이터셋 연결 확인"""
        return False  # 간단한 구현

    async def _has_technical_separation(self, issuer: str, state: StateDB) -> bool:
        """기술적 분리 확인"""
        return True  # 간단한 구현

    async def _check_unauthorized_government_sharing(self, issuer: str, user: str, state: StateDB) -> bool:
        """무단 정부 공유 확인"""
        return False  # 간단한 구현

    async def _has_judicial_oversight(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        """사법부 감독 확인"""
        return True  # 간단한 구현

    async def _get_jurisdiction(self, address: str, state: StateDB) -> str:
        """관할권 조회"""
        # 간단한 구현 - 주소 기반 관할권 결정
        addr_int = int(address[-10:], 16) % 10
        if addr_int < 3:
            return "US"
        elif addr_int < 6:
            return "EU"
        else:
            return "KR"

    async def _has_adequacy_decision(self, origin: str, dest: str, state: StateDB) -> bool:
        """적정성 결정 확인"""
        adequacy_map = {
            ("EU", "KR"): True,
            ("KR", "EU"): True,
            ("US", "EU"): False,
            ("EU", "US"): False
        }
        return adequacy_map.get((origin, dest), False)

    async def _has_standard_contractual_clauses(self, issuer: str, state: StateDB) -> bool:
        """표준 계약 조항 확인"""
        return True  # 간단한 구현

    async def _meets_derogation_conditions(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        """적용 제외 조건 확인"""
        return False  # 간단한 구현

    async def _has_enhanced_protection(self, issuer: str, state: StateDB) -> bool:
        """강화된 보호 확인"""
        return True  # 간단한 구현

    async def _execute_contract_call(self, state: StateDB, contract_addr: str, method: str, params: Dict) -> Dict:
        """계약 호출 실행"""
        # 간단한 시뮬레이션
        return {"is_compliant": True, "violations": []}

    # 강화된 검증 메서드들 (간단한 구현)
    async def _check_enhanced_consent_verification(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        return True

    async def _check_anti_profiling_measures(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        return True

    async def _check_data_minimization_compliance(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        return True

    async def _check_transparency_requirements(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        return True

    async def _check_individual_rights_protection(self, context: TransactionPrivacyContext, state: StateDB) -> bool:
        return True


class PrivacyPoSConfig:
    """Privacy-PoS 설정"""


class PrivacyPoSConfig:
    """Privacy-PoS 설정"""

    def __init__(self, **kwargs):
        self.period = kwargs.get('period', 3)
        self.epoch_length = kwargs.get('epoch_length', 30000)
        self.privacy_threshold = kwargs.get('privacy_threshold', 67)
        self.consent_manager_address = kwargs.get('consent_manager_address', '')
        self.sparql_validator_address = kwargs.get('sparql_validator_address', '')
        self.staking_contract_address = kwargs.get('staking_contract_address', '')
        self.min_validators = kwargs.get('min_validators', 3)
        self.max_validators = kwargs.get('max_validators', 21)
        self.privacy_oracle_reward = kwargs.get('privacy_oracle_reward', 1000000000000000000)  # 1 ETH
        self.slashing_penalty = kwargs.get('slashing_penalty', 5000000000000000000)  # 5 ETH
        self.validation_timeout_seconds = kwargs.get('validation_timeout_seconds', 10)


class PrivacyPoS:
    """Privacy-PoS 메인 합의 엔진"""

    def __init__(self, config: PrivacyPoSConfig, database: Database):
        self.config = config
        self.db = database

        # 검증자 관리
        self.validators: Dict[str, Validator] = {}
        self.validators_list: List[str] = []
        self.current_proposer: str = ""

        # 개인정보보호 검증
        self.privacy_oracle = PrivacyOracle(config.__dict__)
        self.pending_txs: Dict[str, PrivacyValidationResult] = {}

        # 서명 관리
        self.signer: str = ""
        self.sign_fn = None
        self.sign_tx_fn = None

        logger.info("Privacy-PoS consensus engine initialized")

    def author(self, header: BlockHeader) -> str:
        """블록을 채굴한 계정의 주소 반환"""
        return self._extract_signer(header)

    async def verify_header(self, chain: ChainHeaderReader, header: BlockHeader, seal: bool = True) -> bool:
        """헤더가 합의 규칙을 준수하는지 확인"""
        return await self._verify_header(chain, header, None)

    async def verify_headers(self,
                             chain: ChainHeaderReader,
                             headers: List[BlockHeader],
                             seals: List[bool]) -> List[bool]:
        """헤더 배치 검증"""
        results = []

        for i, header in enumerate(headers):
            try:
                result = await self._verify_header(chain, header, headers[:i])
                results.append(result)
            except Exception as e:
                logger.error(f"Header verification failed: {e}")
                results.append(False)

        return results

    async def verify_uncles(self, block: Block) -> bool:
        """블록의 엉클이 합의 규칙을 준수하는지 확인"""
        if len(block.uncles) > 0:
            raise ValidationError("Uncles not allowed in Privacy-PoS")
        return True

    async def prepare(self, chain: ChainHeaderReader, header: BlockHeader) -> None:
        """거래 실행을 위한 헤더의 모든 합의 필드 준비"""
        parent = await chain.get_header(header.parent_hash, header.number - 1)
        if parent is None:
            raise ValidationError("Unknown ancestor")

        # 올바른 난이도 설정
        header.difficulty = self._calc_difficulty(chain, header.timestamp, parent)

        # 타임스탬프가 올바른 지연을 갖도록 보장
        header.timestamp = parent.timestamp + self.config.period
        if header.timestamp < int(time.time()):
            header.timestamp = int(time.time())

    async def finalize(self,
                       chain: ChainHeaderReader,
                       header: BlockHeader,
                       state: StateDB,
                       txs: List[Transaction],
                       uncles: List[BlockHeader]) -> None:
        """블록을 완료하고 최종 상태 설정"""

        # 1. 개인정보보호 규정준수 검증 (핵심!)
        logger.info(f"Starting privacy compliance validation, block: {header.number}, txs: {len(txs)}")

        for i, tx in enumerate(txs):
            try:
                await self.privacy_oracle.validate_transaction_privacy(tx, state, header)
            except PrivacyViolationError as e:
                logger.error(f"Transaction {i} failed privacy validation: {e}")
                raise ValidationError(f"Transaction {i} failed privacy validation: {e}")

        # 2. 개인정보보호 증명 생성
        privacy_proof = await self._generate_privacy_proof(txs, header, state)

        # 3. 헤더 Extra Data에 개인정보보호 증명 포함
        if len(header.extra_data) < Constants.EXTRA_VANITY:
            header.extra_data += b'\x00' * (Constants.EXTRA_VANITY - len(header.extra_data))
        header.extra_data += privacy_proof

        # 4. 보상 적립
        await self._accumulate_rewards(state, header)

        # 5. 필요시 검증자 세트 업데이트
        if self._is_epoch_transition(header.number):
            await self._update_validator_set(state, header)

    async def finalize_and_assemble(self,
                                    chain: ChainHeaderReader,
                                    header: BlockHeader,
                                    state: StateDB,
                                    txs: List[Transaction],
                                    uncles: List[BlockHeader]) -> Block:
        """블록을 완료하고 조립"""

        # 블록 완료
        await self.finalize(chain, header, state, txs, uncles)

        # 블록 조립 후 반환
        return Block(header=header, transactions=txs, uncles=uncles)

    async def seal(self,
                   chain: ChainHeaderReader,
                   block: Block,
                   stop_channel: asyncio.Event) -> Optional[Block]:
        """로컬 서명 자격 증명을 사용하여 봉인된 블록 생성 시도"""

        header = block.header

        # 제네시스 블록 봉인은 지원되지 않음
        if header.number == 0:
            raise ValidationError("Sealing the genesis block is not supported")

        # 기간이 0이고 미래 타임스탬프인 경우 거부
        if self.config.period == 0 and header.timestamp > int(time.time()):
            raise ValidationError("This node is not the proposer")

        # 이 블록의 제안자인지 확인
        proposer = await self._get_proposer(chain, header.number, header.parent_hash)
        if proposer != self.signer:
            raise ValidationError("This node is not the proposer")

        # 블록 생성 시간까지 대기
        delay = header.timestamp - int(time.time())
        if delay > 0:
            logger.info(f"Waiting for slot to sign and propagate, delay: {delay}s")
            try:
                await asyncio.wait_for(stop_channel.wait(), timeout=delay)
                return None  # 중단됨
            except asyncio.TimeoutError:
                pass  # 계속 진행

        # 블록 서명
        sighash = self._sign_hash(header)

        if self.sign_fn is None:
            raise ValidationError("Signing function not set")

        sig = await self.sign_fn(self.signer, sighash)

        # 헤더 extra data에 서명 포함
        header.extra_data = header.extra_data[:-Constants.EXTRA_SEAL] + sig

        return Block(header=header, transactions=block.transactions, uncles=block.uncles)

    def seal_hash(self, header: BlockHeader) -> str:
        """봉인되기 전 블록의 해시 반환"""
        return self._seal_hash(header)

    def _calc_difficulty(self, chain: ChainHeaderReader, timestamp: int, parent: BlockHeader) -> int:
        """난이도 조정 알고리즘"""
        return 1  # Privacy-PoS에서는 고정 난이도

    def close(self) -> None:
        """합의 엔진 종료 (Privacy-PoS는 백그라운드 스레드가 없으므로 noop)"""
        logger.info("Privacy-PoS consensus engine closed")

    # 내부 헬퍼 메서드들

    async def _verify_header(self,
                             chain: ChainHeaderReader,
                             header: BlockHeader,
                             parents: Optional[List[BlockHeader]]) -> bool:
        """헤더 검증 로직"""

        # 기본 헤더 검증
        if header.number == 0:
            return True  # 제네시스 블록

        # 부모 블록 확인
        parent = await chain.get_header(header.parent_hash, header.number - 1)
        if parent is None:
            raise ValidationError(f"Unknown parent block: {header.parent_hash}")

        # 타임스탬프 검증
        if header.timestamp <= parent.timestamp:
            raise ValidationError("Invalid timestamp")

        # 난이도 검증
        expected_difficulty = self._calc_difficulty(chain, header.timestamp, parent)
        if header.difficulty != expected_difficulty:
            raise ValidationError("Wrong difficulty")

        # 서명 검증
        if not await self._verify_signature(header):
            raise ValidationError("Invalid signature")

        # 개인정보보호 증명 검증
        if not await self._verify_privacy_proof(header):
            raise ValidationError("Invalid privacy proof")

        return True

    async def _generate_privacy_proof(self,
                                      txs: List[Transaction],
                                      header: BlockHeader,
                                      state: StateDB) -> bytes:
        """개인정보보호 증명 생성"""

        proof_data = {
            "block_number": header.number,
            "timestamp": header.timestamp,
            "transaction_count": len(txs),
            "privacy_validated": True,
            "privacy_oracle_version": "1.0"
        }

        # 각 거래의 개인정보보호 상태 포함
        tx_proofs = []
        for tx in txs:
            risk_score = self.privacy_oracle._calculate_privacy_risk_score(
                await self.privacy_oracle._extract_transaction_context(tx, state)
            )
            tx_proofs.append({
                "tx_hash": tx.hash,
                "privacy_compliant": True,
                "risk_score": risk_score
            })

        proof_data["transaction_proofs"] = tx_proofs

        # JSON으로 직렬화하고 해시 생성
        proof_json = json.dumps(proof_data, sort_keys=True)
        proof_hash = hashlib.sha256(proof_json.encode()).digest()

        return proof_hash

    async def _accumulate_rewards(self, state: StateDB, header: BlockHeader) -> None:
        """블록 및 개인정보보호 검증 보상 적립"""

        # 기본 블록 보상
        block_reward = 1000000000000000000  # 1 ETH
        current_balance = await state.get_balance(header.coinbase)
        await state.set_balance(header.coinbase, current_balance + block_reward)

        # 개인정보보호 오라클 보상
        privacy_reward = self.config.privacy_oracle_reward
        await state.set_balance(header.coinbase,
                                await state.get_balance(header.coinbase) + privacy_reward)

        logger.debug(f"Rewards accumulated for block {header.number}, "
                     f"coinbase: {header.coinbase}, "
                     f"block_reward: {block_reward}, "
                     f"privacy_reward: {privacy_reward}")

    def _is_epoch_transition(self, block_number: int) -> bool:
        """에포크 전환 여부 확인"""
        return block_number % self.config.epoch_length == 0

    async def _update_validator_set(self, state: StateDB, header: BlockHeader) -> None:
        """검증자 세트 업데이트"""

        logger.info(f"Updating validator set at epoch transition, block: {header.number}")

        # 스테이킹 계약에서 새로운 검증자 목록 조회
        staking_contract = self.config.staking_contract_address
        validator_data = await state.get_contract_data(staking_contract, "active_validators")

        if validator_data:
            new_validators = validator_data.get("validators", [])

            # 검증자 목록 업데이트
            self.validators.clear()
            self.validators_list.clear()

            for validator_info in new_validators:
                validator = Validator(
                    address=validator_info["address"],
                    public_key=validator_info["public_key"],
                    stake=validator_info["stake"],
                    privacy_score=validator_info.get("privacy_score", 50),
                    is_active=True,
                    joined_epoch=header.number // self.config.epoch_length
                )

                self.validators[validator.address] = validator
                self.validators_list.append(validator.address)

            logger.info(f"Updated validator set: {len(self.validators)} validators")

    async def _get_proposer(self,
                            chain: ChainHeaderReader,
                            block_number: int,
                            parent_hash: str) -> str:
        """현재 블록의 제안자 결정"""

        if not self.validators_list:
            raise ValidationError("No validators available")

        # 간단한 라운드 로빈 방식으로 제안자 선택
        # 실제 구현에서는 더 정교한 선택 알고리즘 사용
        proposer_index = block_number % len(self.validators_list)
        return self.validators_list[proposer_index]

    def _extract_signer(self, header: BlockHeader) -> str:
        """헤더에서 서명자 추출"""
        # 간단한 구현 - 실제로는 서명에서 공개키 복구
        return header.coinbase

    def _sign_hash(self, header: BlockHeader) -> bytes:
        """헤더의 서명 해시 생성"""
        # 서명할 헤더 데이터 준비 (서명 부분 제외)
        header_data = {
            "parent_hash": header.parent_hash,
            "number": header.number,
            "timestamp": header.timestamp,
            "coinbase": header.coinbase,
            "difficulty": header.difficulty,
            "gas_limit": header.gas_limit,
            "gas_used": header.gas_used,
            "extra_data": header.extra_data[:-Constants.EXTRA_SEAL].hex()
        }

        header_json = json.dumps(header_data, sort_keys=True)
        return hashlib.sha256(header_json.encode()).digest()

    def _seal_hash(self, header: BlockHeader) -> str:
        """봉인 해시 계산"""
        return hashlib.sha256(self._sign_hash(header)).hexdigest()

    async def _verify_signature(self, header: BlockHeader) -> bool:
        """헤더 서명 검증"""
        # 간단한 구현 - 실제로는 서명 검증 로직
        return len(header.extra_data) >= Constants.EXTRA_SEAL

    async def _verify_privacy_proof(self, header: BlockHeader) -> bool:
        """개인정보보호 증명 검증"""
        # 헤더에 개인정보보호 증명이 포함되어 있는지 확인
        return len(header.extra_data) >= Constants.EXTRA_VANITY + 32  # 32바이트 개인정보보호 해시


# API 클래스 - PrivacyPoS 클래스 외부로 이동
class PrivacyPoSAPI:
    """Privacy-PoS RPC API"""

    def __init__(self, chain: ChainHeaderReader, privacypos: 'PrivacyPoS'):
        self.chain = chain
        self.privacypos = privacypos

    async def get_validators(self) -> List[Dict[str, Any]]:
        """현재 검증자 목록 반환"""
        validators = []
        for addr, validator in self.privacypos.validators.items():
            validators.append({
                "address": validator.address,
                "stake": validator.stake,
                "privacy_score": validator.privacy_score,
                "is_active": validator.is_active,
                "joined_epoch": validator.joined_epoch
            })
        return validators

    async def get_privacy_validation_result(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """거래의 개인정보보호 검증 결과 반환"""
        if tx_hash in self.privacypos.pending_txs:
            result = self.privacypos.pending_txs[tx_hash]
            return {
                "is_compliant": result.is_compliant,
                "violations": result.violations,
                "risk_score": result.risk_score,
                "validator_votes": result.validator_votes,
                "timestamp": result.timestamp
            }
        return None

    async def get_proposer(self, block_number: int) -> str:
        """특정 블록의 제안자 반환"""
        # 부모 해시는 실제 체인에서 조회
        header = await self.chain.get_header_by_number(block_number - 1)
        parent_hash = header.parent_hash if header else "0x" + "0" * 64

        return await self.privacypos._get_proposer(self.chain, block_number, parent_hash)

    async def get_privacy_oracle_status(self) -> Dict[str, Any]:
        """개인정보보호 오라클 상태 반환"""
        return {
            "cache_size": len(self.privacypos.privacy_oracle.validation_cache),
            "risk_cache_size": len(self.privacypos.privacy_oracle.risk_score_cache),
            "config": self.privacypos.privacy_oracle.config
        }


# 메모리 데이터베이스 구현 (테스트용)
class MemoryDatabase(Database):
    def __init__(self):
        self.data = {}

    async def get(self, key: str) -> Optional[bytes]:
        return self.data.get(key)

    async def put(self, key: str, value: bytes):
        self.data[key] = value


# 메모리 상태 DB 구현 (테스트용)
class MemoryStateDB(StateDB):
    def __init__(self):
        self.balances = {}
        self.contract_data = {}

    async def get_balance(self, address: str) -> int:
        return self.balances.get(address, 0)

    async def set_balance(self, address: str, balance: int):
        self.balances[address] = balance

    async def get_contract_data(self, address: str, key: str) -> Any:
        return self.contract_data.get(f"{address}:{key}")

    async def set_contract_data(self, address: str, key: str, value: Any):
        self.contract_data[f"{address}:{key}"] = value


# 사용 예시
async def main():
    """Privacy-PoS 사용 예시"""

    # 설정
    config = PrivacyPoSConfig(
        period=3,
        epoch_length=30000,
        privacy_threshold=67,
        consent_manager_address="0x1000000000000000000000000000000000000001",
        sparql_validator_address="0x1000000000000000000000000000000000000002"
    )

    # Privacy-PoS 엔진 생성
    db = MemoryDatabase()
    consensus = PrivacyPoS(config, db)

    # 샘플 트랜잭션
    tx = Transaction(
        hash="0xabc123",
        from_address="0x7df9a875a174b3bc565e6424a0050ebc1b2d1d82",
        to_address="0xf41c74c9ae680c1aa78f42e5647a62f353b7bdde",
        value=1000,
        data=b'',
        gas=21000,
        gas_price=1000000000,
        nonce=1,
        purpose="medical_payment"
    )

    # 상태 DB 설정
    state = MemoryStateDB()

    # 기본 동의 설정
    await state.set_contract_data(
        config.consent_manager_address,
        f"consent_{tx.from_address}_{tx.purpose}_{tx.to_address}",
        {
            "is_active": True,
            "expiry_timestamp": int(time.time()) + 3600,
            "allows_sensitive": True
        }
    )

    # 민감 데이터 동의 추가 설정 (medical_payment는 민감 데이터)
    await state.set_contract_data(
        config.consent_manager_address,
        f"sensitive_consent_{tx.from_address}_{tx.purpose}",
        {
            "allows_sensitive": True,
            "expiry_timestamp": int(time.time()) + 3600,
            "is_active": True
        }
    )

    # 블록 헤더
    header = BlockHeader(
        parent_hash="0x" + "0" * 64,
        number=1,
        timestamp=int(time.time()),
        coinbase="0x7df9a875a174b3bc565e6424a0050ebc1b2d1d82"
    )

    try:
        # 개인정보보호 검증 수행
        await consensus.privacy_oracle.validate_transaction_privacy(tx, state, header)
        logger.info("Transaction privacy validation successful!")

        # 블록 완료
        await consensus.finalize(None, header, state, [tx], [])
        logger.info("Block finalization successful!")

    except Exception as e:
        logger.error(f"Validation failed: {e}")


if __name__ == "__main__":
    # 예시 실행
    asyncio.run(main())
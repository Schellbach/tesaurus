#!/usr/bin/env python3
"""
High-Performance Agent Vault Module for Tesaurus Bitcoin Vault

This module implements an optimized agent engine for making Bitcoin transaction decisions
with focus on performance, memory efficiency, and low latency inference.
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import pickle
from pathlib import Path

# Performance-optimized imports
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import aiohttp
import uvloop  # High-performance event loop
from cachetools import TTLCache, LRUCache
import psutil
import redis.asyncio as redis

# Logging configuration for performance
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('agent_vault.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TransactionContext:
    """Transaction context for agent decision making"""
    amount: float
    destination: str
    inactivity_duration_hours: float
    fee_rate: float
    block_height: int
    time_of_day: int
    day_of_week: int
    historical_patterns: List[Dict[str, float]]

@dataclass
class AgentDecision:
    """agent decision with confidence score"""
    decision: str  # 'approve', 'reject', 'review'
    confidence: float
    reasoning: str
    processing_time_ms: float

class PerformanceMonitor:
    """Monitor agent performance metrics"""
    
    def __init__(self):
        self.decisions_made = 0
        self.total_processing_time = 0.0
        self.cache_hits = 0
        self.cache_misses = 0
        self.model_loads = 0
        
    def record_decision(self, processing_time: float, cache_hit: bool = False):
        """Record a decision for performance tracking"""
        self.decisions_made += 1
        self.total_processing_time += processing_time
        
        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
    
    def get_stats(self) -> Dict[str, float]:
        """Get performance statistics"""
        avg_time = (self.total_processing_time / self.decisions_made 
                   if self.decisions_made > 0 else 0.0)
        cache_hit_rate = (self.cache_hits / (self.cache_hits + self.cache_misses)
                         if (self.cache_hits + self.cache_misses) > 0 else 0.0)
        
        return {
            'decisions_made': self.decisions_made,
            'avg_processing_time_ms': avg_time * 1000,
            'cache_hit_rate': cache_hit_rate,
            'model_loads': self.model_loads,
            'memory_usage_mb': psutil.Process().memory_info().rss / 1024 / 1024
        }

class OptimizedAgentEngine:
    """High-performance agent engine for Bitcoin vault decisions"""
    
    def __init__(self, model_path: str = "./models/tesaurus_agent.pkl", 
                 redis_url: str = "redis://localhost:6379"):
        self.model_path = Path(model_path)
        self.redis_url = redis_url
        
        # Performance optimizations
        self.decision_cache = TTLCache(maxsize=10000, ttl=300)  # 5-minute TTL
        self.feature_cache = LRUCache(maxsize=5000)
        self.model_cache = {}
        
        # Thread pool for CPU-intensive operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=min(4, (psutil.cpu_count() or 1) + 1)
        )
        
        # Performance monitoring
        self.monitor = PerformanceMonitor()
        
        # Model components
        self.scaler: Optional[StandardScaler] = None
        self.anomaly_detector: Optional[IsolationForest] = None
        self.model_version = "1.0.0"
        
        # Redis connection for distributed caching
        self.redis_client: Optional[redis.Redis] = None
        
        # Pre-compiled patterns for faster matching
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile common patterns for faster processing"""
        self.suspicious_patterns = {
            'large_round_amounts': [1.0, 5.0, 10.0, 50.0, 100.0],
            'unusual_hours': list(range(0, 6)) + list(range(23, 24)),
            'high_fee_rates': [100, 200, 500, 1000],  # sat/vB
        }
    
    async def initialize(self):
        """Initialize the agent engine with performance optimizations"""
        logger.info("Initializing agent engine...")
        
        # Set up high-performance event loop
        if isinstance(asyncio.get_event_loop(), uvloop.Loop):
            logger.info("Using uvloop for high performance")
        
        # Initialize Redis connection for distributed caching
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Connected to Redis for distributed caching")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Using local cache only.")
            self.redis_client = None
        
        # Load or create model
        await self._load_or_create_model()
        
        logger.info("agent engine initialized successfully")
    
    async def _load_or_create_model(self):
        """Load existing model or create a new one with optimizations"""
        if self.model_path.exists():
            try:
                # Load model in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                model_data = await loop.run_in_executor(
                    self.thread_pool, self._load_model_sync
                )
                
                self.scaler = model_data['scaler']
                self.anomaly_detector = model_data['anomaly_detector']
                self.model_version = model_data.get('version', '1.0.0')
                
                logger.info(f"Loaded model version {self.model_version}")
                self.monitor.model_loads += 1
                
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                await self._create_default_model()
        else:
            await self._create_default_model()
    
    def _load_model_sync(self) -> Dict[str, Any]:
        """Synchronous model loading for thread pool execution"""
        return joblib.load(self.model_path)
    
    async def _create_default_model(self):
        """Create a default model with reasonable parameters"""
        logger.info("Creating default agent model...")
        
        # Create default scaler
        self.scaler = StandardScaler()
        
        # Create anomaly detector optimized for Bitcoin transactions
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # 10% anomaly rate
            random_state=42,
            n_jobs=-1,  # Use all CPU cores
            warm_start=True  # Allow incremental learning
        )
        
        # Generate synthetic training data for initialization
        synthetic_data = self._generate_synthetic_training_data()
        
        # Train on synthetic data
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self.thread_pool, self._train_model_sync, synthetic_data
        )
        
        # Save model
        await self._save_model()
        
        logger.info("Default model created and trained")
    
    def _generate_synthetic_training_data(self) -> np.ndarray:
        """Generate synthetic training data for model initialization"""
        np.random.seed(42)
        
        # Generate 1000 normal transactions
        normal_data = []
        for _ in range(800):
            features = [
                np.random.lognormal(0, 1),  # amount (log-normal distribution)
                np.random.uniform(0, 168),  # inactivity hours
                np.random.uniform(1, 50),   # fee rate
                np.random.randint(0, 24),   # hour of day
                np.random.randint(0, 7),    # day of week
                np.random.uniform(0, 1),    # pattern consistency
                np.random.uniform(0, 1),    # timing score
            ]
            normal_data.append(features)
        
        # Generate 200 anomalous transactions
        anomaly_data = []
        for _ in range(200):
            features = [
                np.random.uniform(10, 1000),  # Large amounts
                np.random.uniform(0, 1),      # Very short inactivity
                np.random.uniform(100, 1000), # High fees
                np.random.choice([2, 3, 4]),  # Unusual hours
                np.random.randint(0, 7),      # day of week
                np.random.uniform(0, 0.3),    # Low pattern consistency
                np.random.uniform(0, 0.3),    # Low timing score
            ]
            anomaly_data.append(features)
        
        return np.array(normal_data + anomaly_data)
    
    def _train_model_sync(self, data: np.ndarray):
        """Synchronous model training for thread pool execution"""
        # Fit scaler
        self.scaler.fit(data)
        
        # Scale data
        scaled_data = self.scaler.transform(data)
        
        # Train anomaly detector
        self.anomaly_detector.fit(scaled_data)
    
    async def _save_model(self):
        """Save model to disk asynchronously"""
        model_data = {
            'scaler': self.scaler,
            'anomaly_detector': self.anomaly_detector,
            'version': self.model_version,
            'created_at': time.time()
        }
        
        # Ensure model directory exists
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save in thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self.thread_pool, joblib.dump, model_data, self.model_path
        )
    
    async def make_decision(self, context: TransactionContext) -> AgentDecision:
        """Make agent decision with performance optimizations"""
        start_time = time.time()
        
        # Create cache key
        cache_key = self._create_cache_key(context)
        
        # Check local cache first
        if cache_key in self.decision_cache:
            decision = self.decision_cache[cache_key]
            self.monitor.record_decision(time.time() - start_time, cache_hit=True)
            return decision
        
        # Check Redis cache if available
        if self.redis_client:
            try:
                cached_decision = await self.redis_client.get(f"decision:{cache_key}")
                if cached_decision:
                    decision = AgentDecision(**json.loads(cached_decision))
                    self.decision_cache[cache_key] = decision
                    self.monitor.record_decision(time.time() - start_time, cache_hit=True)
                    return decision
            except Exception as e:
                logger.warning(f"Redis cache read failed: {e}")
        
        # Perform inference
        decision = await self._perform_inference(context)
        
        # Cache the decision
        self.decision_cache[cache_key] = decision
        
        # Cache in Redis if available
        if self.redis_client:
            try:
                await self.redis_client.setex(
                    f"decision:{cache_key}", 
                    300,  # 5-minute TTL
                    json.dumps(asdict(decision))
                )
            except Exception as e:
                logger.warning(f"Redis cache write failed: {e}")
        
        processing_time = time.time() - start_time
        decision.processing_time_ms = processing_time * 1000
        self.monitor.record_decision(processing_time)
        
        return decision
    
    def _create_cache_key(self, context: TransactionContext) -> str:
        """Create a cache key from transaction context"""
        # Create a hash of the important context features
        key_data = f"{context.amount}:{context.destination}:{context.inactivity_duration_hours}:{context.fee_rate}:{context.block_height}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    async def _perform_inference(self, context: TransactionContext) -> AgentDecision:
        """Perform agent inference with optimized feature extraction"""
        # Extract features efficiently
        features = await self._extract_features(context)
        
        # Run inference in thread pool
        loop = asyncio.get_event_loop()
        anomaly_score, risk_factors = await loop.run_in_executor(
            self.thread_pool, self._compute_anomaly_score, features
        )
        
        # Make decision based on score and rules
        decision, confidence, reasoning = self._make_decision_from_score(
            anomaly_score, risk_factors, context
        )
        
        return AgentDecision(
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            processing_time_ms=0.0  # Will be set by caller
        )
    
    async def _extract_features(self, context: TransactionContext) -> np.ndarray:
        """Extract features optimized for performance"""
        # Check feature cache
        feature_key = f"feat_{hash(str(context))}"
        if feature_key in self.feature_cache:
            return self.feature_cache[feature_key]
        
        # Extract features
        features = [
            context.amount,
            context.inactivity_duration_hours,
            context.fee_rate,
            context.time_of_day,
            context.day_of_week,
            self._calculate_pattern_consistency(context.historical_patterns),
            self._calculate_timing_score(context),
        ]
        
        features_array = np.array([features])
        
        # Cache features
        self.feature_cache[feature_key] = features_array
        
        return features_array
    
    def _compute_anomaly_score(self, features: np.ndarray) -> Tuple[float, Dict[str, float]]:
        """Compute anomaly score and risk factors"""
        # Scale features
        scaled_features = self.scaler.transform(features)
        
        # Get anomaly score
        anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
        
        # Calculate individual risk factors
        risk_factors = {
            'amount_risk': self._assess_amount_risk(features[0][0]),
            'timing_risk': self._assess_timing_risk(features[0][3], features[0][4]),
            'fee_risk': self._assess_fee_risk(features[0][2]),
            'pattern_risk': 1.0 - features[0][5],  # Low consistency = high risk
        }
        
        return anomaly_score, risk_factors
    
    def _assess_amount_risk(self, amount: float) -> float:
        """Assess risk based on transaction amount"""
        if amount in self.suspicious_patterns['large_round_amounts']:
            return 0.8
        elif amount > 10.0:
            return 0.6
        elif amount > 1.0:
            return 0.3
        else:
            return 0.1
    
    def _assess_timing_risk(self, hour: int, day: int) -> float:
        """Assess risk based on timing"""
        risk = 0.0
        
        if hour in self.suspicious_patterns['unusual_hours']:
            risk += 0.4
        
        # Weekend transactions slightly more risky
        if day in [5, 6]:  # Saturday, Sunday
            risk += 0.1
        
        return min(risk, 1.0)
    
    def _assess_fee_risk(self, fee_rate: float) -> float:
        """Assess risk based on fee rate"""
        if fee_rate in self.suspicious_patterns['high_fee_rates']:
            return 0.9
        elif fee_rate > 100:
            return 0.7
        elif fee_rate < 1:
            return 0.5  # Very low fees suspicious
        else:
            return 0.1
    
    def _calculate_pattern_consistency(self, patterns: List[Dict[str, float]]) -> float:
        """Calculate pattern consistency score"""
        if not patterns:
            return 0.0
        
        # Simple consistency metric based on amount variance
        amounts = [p.get('amount', 0) for p in patterns]
        if len(amounts) < 2:
            return 0.5
        
        mean_amount = np.mean(amounts)
        std_amount = np.std(amounts)
        
        # Lower coefficient of variation = higher consistency
        if mean_amount == 0:
            return 0.0
        
        cv = std_amount / mean_amount
        consistency = max(0.0, 1.0 - cv)
        
        return consistency
    
    def _calculate_timing_score(self, context: TransactionContext) -> float:
        """Calculate timing-based score"""
        score = 0.5  # Neutral base score
        
        # Business hours are more trustworthy
        if 9 <= context.time_of_day <= 17:
            score += 0.2
        
        # Weekdays slightly more trustworthy
        if 0 <= context.day_of_week <= 4:
            score += 0.1
        
        # Very late/early hours are suspicious
        if context.time_of_day < 6 or context.time_of_day > 23:
            score -= 0.3
        
        return max(0.0, min(1.0, score))
    
    def _make_decision_from_score(
        self, 
        anomaly_score: float, 
        risk_factors: Dict[str, float], 
        context: TransactionContext
    ) -> Tuple[str, float, str]:
        """Make final decision from anomaly score and risk factors"""
        
        # Combine anomaly score with risk factors
        total_risk = (
            anomaly_score * 0.4 +
            risk_factors['amount_risk'] * 0.3 +
            risk_factors['timing_risk'] * 0.1 +
            risk_factors['fee_risk'] * 0.1 +
            risk_factors['pattern_risk'] * 0.1
        )
        
        # Apply inactivity bonus (longer inactivity = more legitimate recovery)
        inactivity_bonus = min(0.3, context.inactivity_duration_hours / 24.0 * 0.3)
        total_risk -= inactivity_bonus
        
        # Make decision
        if total_risk > 0.7:
            decision = "reject"
            confidence = min(0.95, total_risk)
            reasoning = f"High risk score: {total_risk:.2f}"
        elif total_risk > 0.3:
            decision = "review"
            confidence = 0.6
            reasoning = f"Moderate risk score: {total_risk:.2f}, requires review"
        else:
            decision = "approve"
            confidence = min(0.95, 1.0 - total_risk)
            reasoning = f"Low risk score: {total_risk:.2f}"
        
        # Add specific risk factors to reasoning
        high_risks = [k for k, v in risk_factors.items() if v > 0.5]
        if high_risks:
            reasoning += f". High risk factors: {', '.join(high_risks)}"
        
        return decision, confidence, reasoning
    
    async def batch_decisions(
        self, 
        contexts: List[TransactionContext]
    ) -> List[AgentDecision]:
        """Process multiple decisions in parallel for better performance"""
        tasks = [self.make_decision(context) for context in contexts]
        return await asyncio.gather(*tasks)
    
    async def update_model(self, new_data: List[Tuple[TransactionContext, str]]):
        """Update model with new data (online learning)"""
        if not new_data:
            return
        
        logger.info(f"Updating model with {len(new_data)} new samples")
        
        # Extract features from new data
        features = []
        for context, label in new_data:
            feature_vector = await self._extract_features(context)
            features.append(feature_vector[0])
        
        features_array = np.array(features)
        
        # Update model in thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self.thread_pool, self._update_model_sync, features_array
        )
        
        # Save updated model
        await self._save_model()
        
        logger.info("Model updated successfully")
    
    def _update_model_sync(self, new_features: np.ndarray):
        """Synchronous model update for thread pool execution"""
        # Update scaler (incremental)
        self.scaler.partial_fit(new_features)
        
        # Scale new features
        scaled_features = self.scaler.transform(new_features)
        
        # Update anomaly detector (warm start allows incremental updates)
        self.anomaly_detector.fit(scaled_features)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        stats = self.monitor.get_stats()
        stats.update({
            'cache_size': len(self.decision_cache),
            'feature_cache_size': len(self.feature_cache),
            'model_version': self.model_version,
            'redis_connected': self.redis_client is not None
        })
        return stats
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.redis_client:
            await self.redis_client.close()
        
        self.thread_pool.shutdown(wait=True)
        logger.info("agent engine cleanup completed")

# Example usage and testing
async def main():
    """Main function for testing the agent engine"""
    # Set up high-performance event loop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    
    # Initialize agent engine
    agent_engine = OptimizedAgentEngine()
    await agent_engine.initialize()
    
    # Test with sample transaction
    test_context = TransactionContext(
        amount=0.5,
        destination="tb1qtest123...",
        inactivity_duration_hours=48.0,
        fee_rate=25.0,
        block_height=800000,
        time_of_day=14,
        day_of_week=2,
        historical_patterns=[
            {"amount": 0.3, "frequency": 0.2},
            {"amount": 0.7, "frequency": 0.1}
        ]
    )
    
    # Make decision
    decision = await agent_engine.make_decision(test_context)
    print(f"Decision: {decision.decision}")
    print(f"Confidence: {decision.confidence:.2f}")
    print(f"Reasoning: {decision.reasoning}")
    print(f"Processing time: {decision.processing_time_ms:.2f}ms")
    
    # Performance stats
    stats = agent_engine.get_performance_stats()
    print(f"Performance stats: {stats}")
    
    # Cleanup
    await agent_engine.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
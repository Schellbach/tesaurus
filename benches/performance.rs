//! Performance benchmarks for Tesaurus components

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tesaurus::{
    Config,
    crypto::CryptoManager,
    ai::{AIEngine, TransactionContext},
    storage::StorageManager,
};
use bitcoin::{PrivateKey, Network};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

fn benchmark_crypto_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = Config::default();
    let crypto = rt.block_on(async { 
        Arc::new(CryptoManager::new(&config).await.unwrap()) 
    });

    let mut group = c.benchmark_group("crypto");
    
    // Benchmark key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let key = crypto.generate_private_key().unwrap();
            black_box(key);
        });
    });

    // Benchmark public key derivation
    let private_key = crypto.generate_private_key().unwrap();
    group.bench_function("public_key_derivation", |b| {
        b.iter(|| {
            let pubkey = crypto.derive_public_key(&private_key).unwrap();
            black_box(pubkey);
        });
    });

    // Benchmark multisig address creation
    let pubkeys: Vec<_> = (0..3)
        .map(|_| {
            let pk = crypto.generate_private_key().unwrap();
            crypto.derive_public_key(&pk).unwrap()
        })
        .collect();
    
    group.bench_function("multisig_address_creation", |b| {
        b.iter(|| {
            let address = crypto.create_multisig_address(&pubkeys, 2).unwrap();
            black_box(address);
        });
    });

    // Benchmark signature verification with different cache scenarios
    let message = b"test message for signing";
    let signature = {
        use secp256k1::{Secp256k1, Message, SecretKey};
        let secp = Secp256k1::new();
        let msg = Message::from_slice(&crypto.hash_sha256(message)).unwrap();
        secp.sign_ecdsa(&msg, &private_key.inner)
    };
    let public_key = crypto.derive_public_key(&private_key).unwrap();

    group.bench_function("signature_verification_cold", |b| {
        b.iter(|| {
            // Clear cache before each iteration to simulate cold verification
            crypto.clear_caches();
            let result = rt.block_on(async {
                crypto.verify_signature(message, &signature, &public_key).unwrap()
            });
            black_box(result);
        });
    });

    group.bench_function("signature_verification_cached", |b| {
        // Warm up cache
        rt.block_on(async {
            crypto.verify_signature(message, &signature, &public_key).unwrap();
        });
        
        b.iter(|| {
            let result = rt.block_on(async {
                crypto.verify_signature(message, &signature, &public_key).unwrap()
            });
            black_box(result);
        });
    });

    group.finish();
}

fn benchmark_ai_decisions(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = Config::default();
    let ai_engine = rt.block_on(async {
        Arc::new(AIEngine::new(&config).await.unwrap())
    });

    let mut group = c.benchmark_group("ai");
    group.sample_size(100); // Reduce sample size for AI benchmarks
    
    // Create test contexts with varying complexity
    let simple_context = TransactionContext {
        amount: 50000000, // 0.5 BTC
        destination: "tb1qtest123".to_string(),
        inactivity_duration: Duration::from_secs(3600 * 24), // 24 hours
        fee_rate: 25,
        historical_patterns: vec![],
        block_height: 800000,
    };

    let complex_context = TransactionContext {
        amount: 100000000, // 1.0 BTC
        destination: "tb1qcomplex456".to_string(),
        inactivity_duration: Duration::from_secs(3600 * 48), // 48 hours
        fee_rate: 50,
        historical_patterns: (0..100).map(|i| {
            tesaurus::ai::TransactionPattern {
                amount: 10000000 + (i * 1000000),
                frequency: 0.1 + (i as f64 * 0.001),
                time_of_day: (i % 24) as u8,
                day_of_week: (i % 7) as u8,
            }
        }).collect(),
        block_height: 800100,
    };

    // Benchmark AI decision making with different context complexity
    group.bench_function("decision_simple_context", |b| {
        b.to_async(&rt).iter(|| async {
            let decision = ai_engine.make_decision(&simple_context).await.unwrap();
            black_box(decision);
        });
    });

    group.bench_function("decision_complex_context", |b| {
        b.to_async(&rt).iter(|| async {
            let decision = ai_engine.make_decision(&complex_context).await.unwrap();
            black_box(decision);
        });
    });

    // Benchmark cache performance
    group.bench_function("decision_cached", |b| {
        // Warm up cache
        rt.block_on(async {
            ai_engine.make_decision(&simple_context).await.unwrap();
        });
        
        b.to_async(&rt).iter(|| async {
            let decision = ai_engine.make_decision(&simple_context).await.unwrap();
            black_box(decision);
        });
    });

    // Benchmark batch processing
    let batch_contexts: Vec<_> = (0..10).map(|i| TransactionContext {
        amount: 10000000 + (i * 5000000),
        destination: format!("tb1qbatch{:03}", i),
        inactivity_duration: Duration::from_secs(3600 * (12 + i)),
        fee_rate: 20 + (i * 2),
        historical_patterns: vec![],
        block_height: 800000 + i as u32,
    }).collect();

    group.bench_function("batch_decisions_10", |b| {
        b.to_async(&rt).iter(|| async {
            let decisions = ai_engine.batch_decisions(&batch_contexts).await.unwrap();
            black_box(decisions);
        });
    });

    group.finish();
}

fn benchmark_storage_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = Config::default();
    let storage = rt.block_on(async {
        Arc::new(StorageManager::new(&config).await.unwrap())
    });

    let mut group = c.benchmark_group("storage");
    
    // Test data
    let test_data = "test_data_".repeat(100); // ~1KB of data
    let large_data = "large_test_data_".repeat(10000); // ~160KB of data

    // Benchmark storage operations with different data sizes
    for (size_name, data) in [("small", &test_data), ("large", &large_data)] {
        group.bench_with_input(
            BenchmarkId::new("store", size_name),
            data,
            |b, data| {
                b.to_async(&rt).iter(|| async {
                    let key = format!("benchmark_key_{}", rand::random::<u32>());
                    storage.store(&key, data).await.unwrap();
                    black_box(());
                });
            },
        );
    }

    // Benchmark retrieval (cold vs cached)
    let key = "benchmark_retrieve_key";
    rt.block_on(async {
        storage.store(key, &test_data).await.unwrap();
    });

    group.bench_function("retrieve_cached", |b| {
        b.to_async(&rt).iter(|| async {
            let data: Option<String> = storage.retrieve(key).await.unwrap();
            black_box(data);
        });
    });

    // Benchmark batch operations
    let batch_data: Vec<_> = (0..100)
        .map(|i| (format!("batch_key_{}", i), format!("batch_value_{}", i)))
        .collect();
    let batch_refs: Vec<_> = batch_data.iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    group.bench_function("batch_store_100", |b| {
        b.to_async(&rt).iter(|| async {
            storage.batch_store(&batch_refs).await.unwrap();
            black_box(());
        });
    });

    group.finish();
}

fn benchmark_end_to_end_transaction(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = Config::default();
    
    let (crypto, ai_engine, storage) = rt.block_on(async {
        let crypto = Arc::new(CryptoManager::new(&config).await.unwrap());
        let ai_engine = Arc::new(AIEngine::new(&config).await.unwrap());
        let storage = Arc::new(StorageManager::new(&config).await.unwrap());
        (crypto, ai_engine, storage)
    });

    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(50); // Reduce sample size for complex benchmarks
    
    // Simulate a complete transaction flow
    group.bench_function("complete_transaction_flow", |b| {
        b.to_async(&rt).iter(|| async {
            // 1. Generate keys
            let primary_key = crypto.generate_private_key().unwrap();
            let override_key = crypto.generate_private_key().unwrap();
            let ai_key = crypto.generate_private_key().unwrap();
            
            // 2. Create multisig address
            let pubkeys = vec![
                crypto.derive_public_key(&primary_key).unwrap(),
                crypto.derive_public_key(&override_key).unwrap(),
                crypto.derive_public_key(&ai_key).unwrap(),
            ];
            let address = crypto.create_multisig_address(&pubkeys, 2).unwrap();
            
            // 3. Create transaction context
            let context = TransactionContext {
                amount: 50000000,
                destination: address.to_string(),
                inactivity_duration: Duration::from_secs(3600 * 12),
                fee_rate: 25,
                historical_patterns: vec![],
                block_height: 800000,
            };
            
            // 4. Get AI decision
            let decision = ai_engine.make_decision(&context).await.unwrap();
            
            // 5. Store transaction record
            let tx_record = tesaurus::storage::PendingTransaction {
                txid: format!("tx_{}", rand::random::<u32>()),
                amount: context.amount,
                destination: context.destination.clone(),
                created_at: std::time::Instant::now(),
                ai_decision: Some(format!("{:?}", decision.decision)),
            };
            storage.store_transaction(&tx_record).await.unwrap();
            
            black_box((address, decision, tx_record));
        });
    });

    group.finish();
}

fn benchmark_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = Config::default();
    let ai_engine = rt.block_on(async {
        Arc::new(AIEngine::new(&config).await.unwrap())
    });

    let mut group = c.benchmark_group("concurrent");
    group.sample_size(20);
    
    // Test concurrent AI decisions
    for concurrency in [1, 2, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::new("ai_decisions", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let contexts: Vec<_> = (0..concurrency).map(|i| TransactionContext {
                        amount: 10000000 + (i as u64 * 5000000),
                        destination: format!("tb1qconcurrent{:03}", i),
                        inactivity_duration: Duration::from_secs(3600 * 12),
                        fee_rate: 25,
                        historical_patterns: vec![],
                        block_height: 800000,
                    }).collect();
                    
                    let futures: Vec<_> = contexts.iter()
                        .map(|ctx| ai_engine.make_decision(ctx))
                        .collect();
                    
                    let decisions = futures::future::try_join_all(futures).await.unwrap();
                    black_box(decisions);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_crypto_operations,
    benchmark_ai_decisions,
    benchmark_storage_operations,
    benchmark_end_to_end_transaction,
    benchmark_concurrent_operations
);
criterion_main!(benches);
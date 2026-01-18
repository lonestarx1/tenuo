# Tenuo Performance

**TL;DR**: Authorization adds **0.004ms** per action. Browser actions take 100-2000ms. Overhead is <0.03%.

---

## The Numbers

| Metric | Value | Context |
|--------|-------|---------|
| **Per-check latency** | 0.004ms (4μs) | 25,000x faster than a click |
| **Throughput** | 268,000 checks/sec | Browser does ~1 action/sec |
| **Workflow overhead** | <0.03% | Effectively zero |
| **Memory per agent** | ~50 KB | 0.1% of browser instance |

### What Each Check Costs

| Operation | Time |
|-----------|------|
| Ed25519 signature verification | 2-3 μs |
| Constraint matching | 0.5-1 μs |
| Audit logging | 0.3-0.5 μs |
| **Total** | **~4 μs** |

---

## What This Means

Browser automation is **I/O bound**, not CPU bound. The slowest part is waiting for pages to load, elements to render, and networks to respond.

| Browser Action | Time | Authorization Overhead |
|----------------|------|----------------------|
| Navigate to URL | 500-2000ms | 0.0002-0.0008% |
| Click button | 100-500ms | 0.0008-0.004% |
| Fill form field | 50-200ms | 0.002-0.008% |

**Tenuo is never the bottleneck.** Even at 10,000 actions/second (near impossible for browsers), overhead would be 4%.

### Real Example

1000 agents, 50 actions/hour each = 50,000 authorizations/hour.

```
50,000 × 0.004ms = 0.2 seconds/hour = 0.006% of compute
```

---

## Verify It Yourself

```bash
python benchmark.py
```

**Output:**
```
============================================================
BENCHMARK RESULTS
============================================================
Authorization Latency (1000 iterations):
  Mean:       0.004 ms
  Median:     0.003 ms
  P95:        0.004 ms

Throughput: 268,064 checks/second

Workflow Overhead (10 actions, realistic delays):
  Browser actions:    2050.0 ms (100.0%)
  Authorization:      0.705 ms (0.03%)
============================================================
```

The benchmark takes ~10 seconds and requires only Tenuo (no browser/LLM).

### Test System

```
MacBook Pro (2023), Apple M3 Max, 14 cores, 36 GB RAM
macOS 26.2, Python 3.12.12, Tenuo 0.1.0b6
```

Your numbers may differ. Run the benchmark on your hardware.

---

## Optimization Tips

### 1. Bind Once, Use Many

```python
# Slow: rebinds every iteration
for action in actions:
    bound = warrant.bind(keypair)
    bound.allows(action, args)

# Fast: bind once, reuse
bound = warrant.bind(keypair)
for action in actions:
    bound.allows(action, args)
```

**Speedup**: ~10x

### 2. Prefer UrlPattern Over Regex

```python
# Slower
.capability("navigate", url=Regex(r"https://([a-z0-9-]+\.)*example\.com/.*"))

# Faster
.capability("navigate", url=UrlPattern("https://*.example.com/*"))
```

Usually negligible, but matters at scale.

---

## Summary

| Question | Answer |
|----------|--------|
| Will Tenuo slow down my agent? | No. 0.004ms vs 100-2000ms browser actions. |
| What's the overhead? | <0.03% of workflow time. |
| Can it handle scale? | 268,000 checks/sec single-threaded. Never the bottleneck. |
| How do I verify? | `python benchmark.py` |

**Bottom line**: Tenuo provides cryptographic authorization at if-statement speed.

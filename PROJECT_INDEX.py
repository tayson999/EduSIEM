"""
PROJECT INDEX & QUICK REFERENCE
================================

Log Analysis & Lightweight SIEM Project
Built with Python | Educational Focus | 5 Learning Phases

PROJECT SIZE: ~85 KB of code, comments, and documentation
"""

print("""

╔════════════════════════════════════════════════════════════════════════╗
║                    SIEM PROJECT - QUICK REFERENCE                    ║
╚════════════════════════════════════════════════════════════════════════╝

📁 PROJECT STRUCTURE
════════════════════════════════════════════════════════════════════════

c:/Users/beshe/Desktop/lessons/siem_project/

├─ 📖 DOCUMENTATION (Start here!)
│  ├─ START_HERE.md                  [👈 READ THIS FIRST]
│  ├─ STEP_BY_STEP_GUIDE.md         (10 learning steps)
│  ├─ README.md                      (Project overview)
│  └─ TEACHING_GUIDE.py              (Detailed concepts)
│
├─ 🔧 CORE MODULES (The SIEM Pipeline)
│  ├─ parsers.py                     (Log parsing with regex)
│  │  └─ ApacheAccessLogParser
│  │     SSHAuthLogParser
│  │     WindowsEventLogParser
│  │
│  ├─ anomaly_detector.py            (3 detection methods)
│  │  ├─ TimeSeriesAggregator
│  │  ├─ StatisticalAnomalyDetector (z-score)
│  │  ├─ MLAnomalyDetector            (Isolation Forest)
│  │  └─ RuleBasedDetector           (Custom rules)
│  │
│  ├─ alerting.py                    (Alert system)
│  │  ├─ Alert
│  │  ├─ AlertManager
│  │  └─ AlertFormatter
│  │
│  └─ siem_engine.py                 (Main orchestration)
│
├─ 📚 LEARNING RESOURCES
│  ├─ quick_examples.py              (Run this for demos)
│  ├─ test_siem.py                   (19 unit tests)
│  └─ requirements.txt               (Dependencies)
│
├─ ⚙️ CONFIGURATION
│  └─ config.yaml                    (Thresholds, sources)
│
└─ 📊 DATA
   ├─ sample_logs/
   │  ├─ apache_access.log           (Apache web server logs)
   │  ├─ ssh_auth.log                (SSH login attempts)
   │  └─ windows_events.log          (Windows events - optional)
   │
   └─ siem_alerts.json               (Generated alerts)


═══════════════════════════════════════════════════════════════════════
🎯 QUICK START (Choose one)
═══════════════════════════════════════════════════════════════════════

Option 1: VIEW EXAMPLES
   python quick_examples.py
   → Shows: parsing, anomaly detection, alerting

Option 2: RUN FULL SIEM
   python siem_engine.py
   → Analyzes sample logs, generates alerts.json

Option 3: RUN TESTS
   python test_siem.py
   → 19 unit tests validating all components


═══════════════════════════════════════════════════════════════════════
📚 LEARNING MODULES
═══════════════════════════════════════════════════════════════════════

MODULE 1: LOG PARSING (parsers.py)
─────────────────────────────────────
What: Convert unstructured text → structured data
How:  Regular expressions (regex)
Learn: Extract fields from any log format
File: parsers.py (~400 lines)

Example:
  Input:  192.168.1.10 - - [05/Dec/2025:14:32:10] "GET /index.html" 200 1234
  Output: {'source_ip': '192.168.1.10', 'method': 'GET', 'status': 200, ...}


MODULE 2: TIME-SERIES AGGREGATION (anomaly_detector.py)
──────────────────────────────────────────────────────────
What: Group events into time windows for analysis
How:  Pandas groupby + rolling windows
Learn: Compute statistics (mean, std, percentiles)
File: anomaly_detector.py (~500 lines)

Example:
  Raw:        1000 events in 1 hour
  Aggregated: 200 events per 5-min bucket
  Stats:      mean=200, std=20


MODULE 3: ANOMALY DETECTION (anomaly_detector.py)
───────────────────────────────────────────────────
What: Find unusual patterns
How:  Three methods (pick one or combine):

Method A: STATISTICAL (z-score)
  Formula: z = (value - mean) / std
  Rule:    |z| > 3 → anomaly
  Speed:   Fast
  File:    StatisticalAnomalyDetector class

Method B: MACHINE LEARNING (Isolation Forest)
  Algorithm: Random partitioning
  Outliers:  Isolate faster → flagged
  Speed:     Medium
  File:      MLAnomalyDetector class

Method C: RULE-BASED
  Logic:   Custom thresholds (e.g., >10 failed logins in 5 min)
  Speed:   Instant
  File:    RuleBasedDetector class


MODULE 4: ALERTING (alerting.py)
─────────────────────────────────
What: Generate structured alerts for humans
How:  Create Alert objects with severity + context
Learn: Deduplication, formatting, severity levels
File: alerting.py (~400 lines)

Severity Levels:
  INFO     → Normal but notable
  WARNING  → Suspicious, needs review
  CRITICAL → Immediate threat


MODULE 5: OUTPUT & REPORTING (alerting.py)
──────────────────────────────────────────────
What: Present findings in different formats
How:  AlertFormatter converts alerts
Learn: Text, JSON, CSV, Slack
File: alerting.py (~200 lines)

Formats:
  TEXT   → Human readable
  JSON   → Machine readable
  CSV    → Excel compatible
  SLACK  → Instant messaging


════════════════════════════════════════════════════════════════════════
🎓 LEARNING PATHS
════════════════════════════════════════════════════════════════════════

BEGINNER (1-2 hours)
─────────────────────
1. Read:  START_HERE.md
2. Read:  STEP_BY_STEP_GUIDE.md (Steps 1-3)
3. Run:   python quick_examples.py
4. Play:  Modify sample_logs/ and re-run

Skills gained:
✓ Understand log formats
✓ Learn regex basics
✓ See parsing in action


INTERMEDIATE (3-6 hours)
─────────────────────────
1. Read:  STEP_BY_STEP_GUIDE.md (Steps 4-7)
2. Read:  parsers.py + anomaly_detector.py code
3. Modify: config.yaml (thresholds)
4. Write: Custom detection rule
5. Run:  python siem_engine.py with your changes

Skills gained:
✓ Understand anomaly detection
✓ Tune detection sensitivity
✓ Write custom detection logic
✓ Interpret alert output


ADVANCED (6+ hours)
────────────────────
1. Read:  All .py files thoroughly
2. Review: Unit tests in test_siem.py
3. Extend: Add new features
   - Windows Event Log parser
   - Flask dashboard
   - Database backend
   - ML model training
4. Deploy: Run on real logs

Skills gained:
✓ Full system architecture
✓ Multi-method anomaly detection
✓ Production-grade logging/alerting
✓ System design & scalability


════════════════════════════════════════════════════════════════════════
🔧 FILE REFERENCE GUIDE
════════════════════════════════════════════════════════════════════════

START_HERE.md (8 KB)
    PURPOSE: Entry point for all learners
    READING TIME: 10 minutes
    KEY SECTIONS:
      - Quick start (5 minutes)
      - Learning path (beginner to advanced)
      - Example output
      - Hands-on exercises
    ACTION: Read this first!

STEP_BY_STEP_GUIDE.md (11 KB)
    PURPOSE: Detailed learning guide (10 steps)
    READING TIME: 30-60 minutes
    COVERS:
      Step 1-3: Log parsing & aggregation
      Step 4-6: Anomaly detection & alerting
      Step 7-10: Full pipeline & extensions
    ACTION: Follow along with code examples

README.md (3 KB)
    PURPOSE: Project overview
    KEY SECTIONS:
      - What you'll learn
      - Project structure
      - Key concepts
      - Example output
    ACTION: Reference material

TEACHING_GUIDE.py (12 KB)
    PURPOSE: Comprehensive teaching material
    KEY SECTIONS:
      - Part 1: Understanding the project
      - Part 2: Pipeline (5 phases)
      - Part 3: Hands-on examples
      - Part 4: Extensions
      - Part 5: Best practices
    ACTION: Deep dive into concepts

quick_examples.py (5 KB)
    PURPOSE: Runnable demonstrations
    SHOWS:
      - Log parsing
      - Anomaly detection
      - Alert generation
    ACTION: Run: python quick_examples.py
    TIME: 2-3 minutes

test_siem.py (12 KB)
    PURPOSE: Unit tests + usage examples
    CONTAINS:
      - 19 test cases
      - Tests for all major components
      - Good for learning via examples
    ACTION: Run: python test_siem.py
    TIME: 5 seconds to run

parsers.py (9 KB)
    PURPOSE: Log parsing with regex
    CLASSES:
      - LogParser (base class)
      - ApacheAccessLogParser
      - SSHAuthLogParser
      - WindowsEventLogParser
      - LogParserFactory
    KEY LEARNING:
      - Regular expressions
      - Pattern matching
      - Field extraction
    CODE LINES: ~350

anomaly_detector.py (14 KB)
    PURPOSE: Anomaly detection algorithms
    CLASSES:
      - TimeSeriesAggregator
      - StatisticalAnomalyDetector (z-score)
      - MLAnomalyDetector (Isolation Forest)
      - RuleBasedDetector
    KEY LEARNING:
      - Time-series aggregation
      - Statistical methods
      - Machine learning
      - Rule-based detection
    CODE LINES: ~450

alerting.py (11 KB)
    PURPOSE: Alert generation & formatting
    CLASSES:
      - Alert
      - Severity (enum)
      - AlertManager
      - AlertFormatter
      - SimpleNotifier
    KEY LEARNING:
      - Alert lifecycle
      - Deduplication
      - Output formatting
    CODE LINES: ~400

siem_engine.py (12 KB)
    PURPOSE: Main orchestration
    CLASS:
      - SIEMEngine
    METHODS:
      - parse_logs()
      - run_statistical_detection()
      - run_ml_detection()
      - run_rule_based_detection()
      - generate_report()
      - run() [main pipeline]
    KEY LEARNING:
      - Component integration
      - Error handling
      - Configuration management
    CODE LINES: ~320

config.yaml (2 KB)
    PURPOSE: Configuration & thresholds
    SECTIONS:
      - detection: algorithm settings
      - alerting: alert config
      - log_sources: input files
      - retention: data retention
    KEY SETTINGS:
      - zscore_threshold: detection sensitivity
      - failed_login_threshold: brute-force detection
      - dedup_window_seconds: alert deduplication


════════════════════════════════════════════════════════════════════════
💡 KEY CONCEPTS AT A GLANCE
════════════════════════════════════════════════════════════════════════

REGEX (Regular Expressions)
  Pattern:  r'(?P<ip>[\d.]+)'
  Matches:  192.168.1.10
  Extracts: IP address into named group

Z-SCORE (Statistical Anomaly Detection)
  Formula:  z = (value - mean) / std
  Rule:     |z| > 3 → anomaly
  Example:  100 logins/min baseline, 500 logins spike → z=20 → ALERT!

ISOLATION FOREST (ML-based Detection)
  Algorithm: Random partitioning + isolation
  Outliers:  Isolate faster than normal points
  Result:    Probability of being anomaly

TIME SERIES AGGREGATION
  Raw:       1,000,000 events
  Bucketed:  Time windows (5-min, 1-hour)
  Result:    Patterns emerge, statistics computed

ALERT DEDUPLICATION
  Problem:   Same attack → 1,000 duplicate alerts
  Solution:  Only alert once per (type, IP) in 5-min window
  Result:    1 alert instead of 1,000


════════════════════════════════════════════════════════════════════════
🚀 NEXT STEPS
════════════════════════════════════════════════════════════════════════

Level 1: GET ORIENTED
  1. Read START_HERE.md
  2. Run quick_examples.py
  3. Review STEP_BY_STEP_GUIDE.md (first 3 steps)

Level 2: UNDERSTAND & EXPERIMENT
  1. Read STEP_BY_STEP_GUIDE.md (all 10 steps)
  2. Modify config.yaml
  3. Create custom sample data
  4. Run siem_engine.py

Level 3: IMPLEMENT & EXTEND
  1. Add Windows Event Log parser
  2. Write custom detection rule
  3. Build Flask dashboard
  4. Integrate with Slack

Level 4: DEPLOY & SCALE
  1. Connect to real log sources
  2. Add database backend (PostgreSQL, Elasticsearch)
  3. Deploy with Docker/Kubernetes
  4. Implement real-time streaming (Kafka)


════════════════════════════════════════════════════════════════════════
❓ FAQ
════════════════════════════════════════════════════════════════════════

Q: Where do I start?
A: Read START_HERE.md, then run python quick_examples.py

Q: How long will this take to learn?
A: 1-2 hours for basics, 6-10 hours for mastery, lifetime for expertise

Q: Can I modify the code?
A: Yes! That's the whole point. Experiment freely.

Q: What if I break something?
A: Git reset, or re-clone. You can't hurt anything.

Q: How do I use this on real logs?
A: Point config.yaml to your log files, adjust thresholds, run siem_engine.py

Q: What's the hardest part?
A: Tuning thresholds to avoid false positives. Requires real data & iteration.

Q: Can I deploy this in production?
A: Yes, with additional hardening: database, authentication, monitoring, etc.

Q: Where can I learn more?
A: Splunk docs, ELK Stack tutorials, machine learning courses


════════════════════════════════════════════════════════════════════════
📞 SUPPORT & DEBUGGING
════════════════════════════════════════════════════════════════════════

Issue: ModuleNotFoundError
Fix:   pip install -r requirements.txt

Issue: No anomalies detected
Fix:   Lower zscore_threshold in config.yaml (3.0 → 2.0)

Issue: Parsing fails
Fix:   Check log format matches parser regex; review sample_logs/

Issue: Slow execution
Fix:   Use smaller log files; optimize aggregation window

Issue: Confused about algorithm
Fix:   Read inline code comments; check test_siem.py examples


════════════════════════════════════════════════════════════════════════

You're all set! Start with START_HERE.md 📖

═══════════════════════════════════════════════════════════════════════
""")

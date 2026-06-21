# P2P & IPFS Usage Guide

## 🌐 P2P Network (Go-based)

### Setup
P2P binary already built: `sentinel_p2p/sentinel_p2p` (2.8MB)

### Usage

#### 1. Start P2P Node
```bash
sentinel-pro> p2p start
```
**Output:**
```
✓ P2P node started
```

#### 2. Check Connected Peers
```bash
sentinel-pro> p2p peers
```
**Output:**
```
Connected peers: 0
```

#### 3. Share IOC (Indicator of Compromise)
```bash
sentinel-pro> p2p share malicious-ip:192.168.1.100
sentinel-pro> p2p share hash:d41d8cd98f00b204e9800998ecf8427e
sentinel-pro> p2p share domain:malicious.com
```

### What P2P Network Does:
- **Gossip Protocol:** Shares threat intelligence with other Sentinel nodes
- **DHT Discovery:** Finds peers automatically
- **Encrypted Channels:** Secure IOC sharing
- **Decentralized:** No central server required

---

## 📦 IPFS (Distributed Storage)

### Installation

```bash
# Run installation script
bash /tmp/ipfs_install.sh

# Or manual install:
cd /tmp
wget https://dist.ipfs.tech/kubo/v0.24.0/kubo_v0.24.0_linux-amd64.tar.gz
tar -xzf kubo_v0.24.0_linux-amd64.tar.gz
cd kubo
sudo bash install.sh
ipfs init
```

### Start IPFS Daemon

**Terminal 1:** (Keep this running)
```bash
ipfs daemon
```

**Output:**
```
Initializing daemon...
API server listening on /ip4/127.0.0.1/tcp/5001
Gateway server listening on /ip4/127.0.0.1/tcp/8080
Daemon is ready
```

### Usage (Terminal 2)

#### 1. Add File to IPFS
```bash
# In Sentinel
sentinel-pro> ipfs add /path/to/evidence.json
```

**Output:**
```
✓ Added to IPFS
  Hash: QmXg9Pp2ytZ62glXHLQV1A7wXBjLB7vUzM
```

**Or CLI:**
```bash
ipfs add evidence.json
# added QmXg9Pp2ytZ62glXHLQV1A7wXBjLB7vUzM evidence.json
```

#### 2. Retrieve File from IPFS
```bash
# In Sentinel
sentinel-pro> ipfs get QmXg9Pp2ytZ62glXHLQV1A7wXBjLB7vUzM
```

**Or CLI:**
```bash
ipfs cat QmXg9Pp2ytZ62glXHLQV1A7wXBjLB7vUzM > downloaded.json
```

#### 3. Pin Evidence (Permanent Storage)
```bash
sentinel-pro> ipfs pin QmXg9Pp2ytZ62glXHLQV1A7wXBjLB7vUzM
```

**Output:**
```
✓ Pinned to IPFS
```

**What Pinning Does:**
- Prevents garbage collection
- Keeps file permanently on your node
- Essential for evidence preservation

---

## 🔗 Real-World Use Cases

### Use Case 1: Evidence Storage (Legal)
```bash
# 1. Scan target
sentinel-pro> bugbounty example.com

# 2. Add report to IPFS
sentinel-pro> ipfs add reports/bugbounty_example_com_*.json

# 3. Pin for permanent storage
sentinel-pro> ipfs pin <hash>

# Result: Immutable, timestamped evidence chain
```

### Use Case 2: IOC Sharing (Threat Intel)
```bash
# 1. Start P2P node
sentinel-pro> p2p start

# 2. Share malicious indicators
sentinel-pro> p2p share ip:192.168.1.100
sentinel-pro> p2p share hash:d41d8cd98f00b204e9800998ecf8427e

# 3. Other Sentinel nodes automatically receive alerts
```

### Use Case 3: Distributed Backup
```bash
# Add screenshots to IPFS
sentinel-pro> ipfs add screenshots/target_20260616.png

# Add database backups
sentinel-pro> ipfs add data/sentinel.db
sentinel-pro> ipfs pin <hash>

# Access from anywhere with hash
```

---

## 📊 Architecture

```
┌─────────────────────────────────────┐
│      Sentinel Pro Instance 1        │
│  ┌──────────┐      ┌──────────┐   │
│  │ P2P Node │──────│   IPFS   │   │
│  └──────────┘      └──────────┘   │
└───────────┬─────────────┬──────────┘
            │             │
     Gossip │             │ Content
    Protocol│             │Addressed
            │             │ Storage
┌───────────┴─────────────┴──────────┐
│      Sentinel Pro Instance 2        │
│  ┌──────────┐      ┌──────────┐   │
│  │ P2P Node │──────│   IPFS   │   │
│  └──────────┘      └──────────┘   │
└─────────────────────────────────────┘
```

---

## 🔐 Security Features

### P2P Network:
- ✅ **Encrypted channels** - TLS 1.3
- ✅ **DHT-based discovery** - Decentralized
- ✅ **Gossip protocol** - Fast propagation
- ✅ **No central server** - Censorship resistant

### IPFS:
- ✅ **Content-addressed** - SHA-256 hashes
- ✅ **Immutable** - Files can't be changed
- ✅ **Distributed** - No single point of failure
- ✅ **Verifiable** - Hash proves integrity

---

## 🛠️ Troubleshooting

### P2P Not Starting?
```bash
# Check if binary exists
ls -lh sentinel_p2p/sentinel_p2p

# Rebuild if needed
cd sentinel_p2p
go build -o sentinel_p2p .
```

### IPFS Commands Failing?
```bash
# Check daemon status
ipfs swarm peers

# Restart daemon
pkill ipfs
ipfs daemon &

# Check connection
ipfs id
```

### No Peers Connecting?
```bash
# Check firewall
sudo ufw status

# Bootstrap to IPFS network
ipfs bootstrap add /dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN
```

---

## 📚 Advanced Usage

### Store Entire Investigation
```bash
# Create investigation package
tar -czf investigation_target.tar.gz investigations/target/*

# Add to IPFS
sentinel-pro> ipfs add investigation_target.tar.gz

# Share hash with team via P2P
sentinel-pro> p2p share investigation:<hash>
```

### Federated Threat Intelligence
```bash
# Terminal 1: Start P2P + IPFS
ipfs daemon &
sentinel-pro> p2p start

# Terminal 2: Share findings
sentinel-pro> bugbounty example.com
sentinel-pro> ipfs add reports/*.json
sentinel-pro> p2p share report:<ipfs_hash>

# Other Sentinel nodes automatically:
# 1. Receive IOC via P2P
# 2. Fetch report from IPFS
# 3. Update local threat database
```

---

## 🎯 Quick Start Checklist

- [ ] Install IPFS: `bash /tmp/ipfs_install.sh`
- [ ] Start IPFS daemon: `ipfs daemon &`
- [ ] Start P2P node: `sentinel-pro> p2p start`
- [ ] Test file upload: `sentinel-pro> ipfs add test.txt`
- [ ] Test IOC sharing: `sentinel-pro> p2p share test:value`
- [ ] Pin important data: `sentinel-pro> ipfs pin <hash>`

---

## 📞 Support

For issues:
- Check logs: `tail -f logs/sentinel.log`
- IPFS logs: `ipfs log tail`
- P2P binary logs: `./sentinel_p2p/sentinel_p2p --debug`

**GitHub:** https://github.com/Mrsultan7890/osints
**Author:** @who_is_the_black_hat

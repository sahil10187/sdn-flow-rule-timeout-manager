
---

# SDN Flow Rule Timeout Manager using Mininet and Ryu

---

## 1. Overview

This project shows how flow rules are managed in Software Defined Networking (SDN) using the Ryu controller and Mininet.

It uses idle timeout and hard timeout to remove unused flow rules and improve switch performance.

---

## 2. Problem Statement

In SDN, switches depend on flow rules installed by the controller.

If flow rules are not removed:

* They remain in the switch for a long time
* Memory gets filled
* Network performance reduces

The goal is to remove unused or old flow rules automatically.

---

## 3. Tools Used

* Mininet
* Ryu Controller
* OpenFlow Protocol
* Open vSwitch
* Python 3
* iperf

---

## 4. Setup and Execution

### Step 1: Create Virtual Environment

```bash
python3 -m venv sdn-env-py39
source sdn-env-py39/bin/activate
```

### Step 2: Install Ryu

```bash
pip install ryu
```

### Step 3: Run Controller

```bash
ryu-manager controller/timeout_controller.py
```

### Step 4: Run Mininet

```bash
sudo mn --custom topology/simple_topo.py --topo simpletopo --controller=remote --switch=ovs
```

### Step 5: Test Connectivity

```bash
h1 ping h2
```

### Step 6: Check Flow Rules

```bash
sudo ovs-ofctl dump-flows s1
```

---

## 5. Expected Output

### Case 1: Continuous Traffic

* Flow rules are installed
* Packet count increases
* Rules remain active

### Case 2: No Traffic

* Stop ping
* After about 10 seconds
* Flow rules are removed

---

## 6. Key Observations

* Flow rules are created when traffic starts
* Idle timeout removes unused rules
* Helps in efficient memory usage
* Prevents stale entries

---

## 7. Conclusion

This project shows how SDN controllers manage flow rules using timeout mechanisms. It improves network efficiency by removing unused entries.

---

## 8. Author

Mohammed Sahil
Student, Networking

---



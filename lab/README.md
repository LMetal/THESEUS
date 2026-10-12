# 🧪 Multi-Hop / Pivoting Lab Environments

This directory contains two preconfigured vulnerable laboratories designed to test and validate multi-hop attack chains and pivot functionality.

---

## 📂 Directory Structure

* **`drupal-drupal/`**: Homogeneous lab using Drupal 8.5.0 for both the pivot and target hosts.
* **`metasploitable-drupal/`**: Heterogeneous lab using Metasploitable 2 as the pivot host and Drupal 8.5.0 as the internal target.
* **`drupal-metasploitable/`**: Heterogeneous lab using Drupal 8.5.0 as the pivot host and Metasploitable 2 as the internal target.


---

## 🛜 Common Network Architecture

Both labs share the same network isolation schema:
* **`net-dmz` (`172.28.0.0/16`)**: Attacker-facing subnet.
* **`net-internal` (`172.30.0.0/16`)**: Isolated subnet, unreachable directly by the attacker.
* **`target-pivot`**: Dual-homed (connected to both subnets). IP: `172.28.0.5` / `172.30.0.5`.
* **`target-internal`**: Isolated (connected only to `net-internal`). IP: `172.30.0.10`.

---

## 🛠️ Usage Instructions

### 1. Attacker Connectivity Setup

Choose how to expose your Metasploit console to the environment:

* **Option A (Host Mode - Recommended)**: If running Metasploit in Docker, start the container using host network sharing:
  ```bash
  docker run --network host -d --name metasploit-container <metasploit-image>
  ```
  This makes the Metasploit listeners (LPORTs) automatically available system-wide and lets it reach local host ports directly.
* **Option B (Bridge Network Connection)**: If running Metasploit in a standard bridge container:
  ```bash
  docker network connect net-dmz <metasploit-container-name>
  ```
  The pivot host will then be reachable at `172.28.0.5`.

---

## 🚀 Scenario 1: Drupal ➡️ Drupal (Homogeneous Hop)

Located in [drupal-drupal/](file:///home/lgalliera/pentagno/lab/drupal-drupal).

### Start Lab
```bash
cd drupal-drupal
docker compose up -d
```

### Attack Flow
1. **Hop 1 Exploitation**: 
   * **Target**: `target-pivot` (`172.28.0.5` or `localhost:8083`)
   * **Module**: `exploit/unix/webapp/drupal_drupalgeddon2`
   * **Payload**: `php/meterpreter/reverse_tcp` or `generic/shell_reverse_tcp`
   * **Result**: Opens `session_1`.
2. **Pivoting**:
   * Post-exploitation on `session_1` discovers subnet `172.30.0.0/16` on `target-pivot`'s second network card.
   * Run `msf_add_route` via `session_1` for `172.30.0.0/16`.
3. **Hop 2 Exploitation**:
   * **Target**: `target-internal` (`172.30.0.10`) routed through `session_1`
   * **Module**: `exploit/unix/webapp/drupal_drupalgeddon2`
   * **Result**: Opens `session_2`.

---

## 🚀 Scenario 2: Metasploitable 2 ➡️ Drupal (Heterogeneous Hop)

Located in [metasploitable-drupal/](file:///home/lgalliera/pentagno/lab/metasploitable-drupal).

### Start Lab
```bash
cd metasploitable-drupal
docker compose up -d
```

### Attack Flow
1. **Hop 1 Exploitation**:
   * **Target**: `target-pivot` (Metasploitable 2) on `172.28.0.5`
   * **Modules**:
     * **Samba**: `exploit/multi/samba/usermap_script` (Port `139`/`445`) — *Highly recommended, yields instant `root` shell.*
     * **Distcc**: `exploit/unix/misc/distcc_exec` (Port `3632`) — *Yields `daemon` shell.*
   * **Result**: Opens `session_1`.
2. **Pivoting**:
   * Post-exploitation on `session_1` discovers subnet `172.30.0.0/16` and adds the pivot route.
3. **Hop 2 Exploitation**:
   * **Target**: `target-internal` (`172.30.0.10` Drupal) routed through `session_1`
   * **Module**: `exploit/unix/webapp/drupal_drupalgeddon2`
   * **Result**: Opens `session_2`.

---

## 💾 Initial Database Configuration (Drupal)

For the Metasploit Drupalgeddon2 module to succeed, the target Drupal sites must have their database initialized (so they don't redirect to the installer):
* For **drupal-drupal** or **metasploitable-drupal**, the pivot Drupal is pre-initialized, but you can configure the internal target `target-internal` (`172.30.0.10`) instantly by copying the sqlite database from the pivot:
  ```bash
  docker exec target-pivot tar -cf - -C /var/www/html/sites/default . | docker exec -i target-internal tar -xf - -C /var/www/html/sites/default
  docker exec target-internal chown -R www-data:www-data /var/www/html/sites/default
  ```

---

## 🚀 Scenario 3: Drupal ➡️ Metasploitable 2 (Heterogeneous Hop)

Located in [drupal-metasploitable/](file:///home/lgalliera/pentagno/lab/drupal-metasploitable).

### Start Lab
```bash
cd drupal-metasploitable
docker compose up -d
```

### Attack Flow
1. **Hop 1 Exploitation**:
   * **Target**: `target-pivot` (Drupal 8.5.0) on `172.28.0.5`
   * **Module**: `exploit/unix/webapp/drupal_drupalgeddon2`
   * **Payload**: `php/meterpreter/reverse_tcp` or `generic/shell_reverse_tcp`
   * **Result**: Opens `session_1`.
2. **Pivoting**:
   * Post-exploitation on `session_1` discovers subnet `172.30.0.0/16` and adds the pivot route.
3. **Hop 2 Exploitation**:
   * **Target**: `target-internal` (`172.30.0.10` Metasploitable 2) routed through `session_1`
   * **Modules**:
     * **Samba**: `exploit/multi/samba/usermap_script` (Port `139`/`445`) — *Highly recommended, yields instant `root` shell.*
     * **Distcc**: `exploit/unix/misc/distcc_exec` (Port `3632`) — *Yields `daemon` shell.*
   * **Result**: Opens `session_2`.


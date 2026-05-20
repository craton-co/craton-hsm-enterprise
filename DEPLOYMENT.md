# Deployment

Reference deployment patterns for a Craton HSM node serving KMIP, participating in a Raft cluster, and fronted by `craton-hsm-auth`. The three patterns below are progressively more isolated. Pick one; do not mix (e.g., a systemd unit inside a container).

This document focuses on topology, isolation, and provisioning. For runtime procedures (key rotation, CRL refresh, failover drills) see [OPERATIONS.md](OPERATIONS.md). For security controls and their rationale see [HARDENING.md](HARDENING.md).

## Assumptions

- Binary name: `craton-hsmd` (illustrative aggregator binary).

> **Note:** `craton-hsmd` is an illustrative aggregator binary **not shipped in this workspace**; the workspace publishes library crates only. Replace every `craton-hsmd` reference below with your embedding application's binary name. The systemd unit, Dockerfile, and Kubernetes manifests are templates you adapt to that binary.

- Listening ports (match [HARDENING.md §6](HARDENING.md)):

  | Port | Purpose |
  |------|---------|
  | 8443/tcp | PKCS#11 front-end / admin API |
  | 5696/tcp | KMIP (TLS) |
  | 9443/tcp | Raft cluster peer traffic |

- Three-node Raft cluster, quorum = 2.
- `cluster_secret` is a 32-byte hex string delivered out-of-band.
- TLS server certs issued by an internal CA; KMIP clients authenticate with mTLS.

## Pattern A: systemd Single-Node

Suitable for dev, HA-passive replicas, or on-prem appliances with managed OS.

### File Layout

```
/opt/craton-hsm/bin/craton-hsmd
/etc/craton-hsm/craton-hsmd.env         # non-secret env (mode=0640)
/etc/craton-hsm/config.toml             # app config (mode=0640)
/etc/craton-hsm/tls/server.crt
/etc/craton-hsm/tls/server.key          # mode=0600, owner craton-hsm
/etc/craton-hsm/tls/ca.crt
/var/lib/craton-hsm/                    # persistent state (LUKS-encrypted)
/var/log/craton-hsm/                    # audit logs (forwarded to SIEM)
```

Create a dedicated system user:

```bash
useradd --system --home-dir /var/lib/craton-hsm --shell /usr/sbin/nologin craton-hsm
install -d -o craton-hsm -g craton-hsm -m 0750 /var/lib/craton-hsm /var/log/craton-hsm
```

### Unit File

`/etc/systemd/system/craton-hsmd.service`:

```ini
[Unit]
Description=Craton HSM daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=craton-hsm
Group=craton-hsm
ExecStart=/opt/craton-hsm/bin/craton-hsmd --config /etc/craton-hsm/config.toml
EnvironmentFile=/etc/craton-hsm/craton-hsmd.env
LoadCredentialEncrypted=cluster_secret:/etc/craton-hsm/creds/cluster_secret.cred

# Capability surface
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Filesystem isolation
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/craton-hsm /var/log/craton-hsm
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectProc=invisible

# Syscall / exec hardening
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete

# Resource limits
LimitNOFILE=65536
LimitNPROC=512
TasksMax=1024

# Restart behavior
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Deliver `cluster_secret` via systemd-creds (encrypted at rest, decrypted only into the unit's credential directory):

```bash
systemd-ask-password | systemd-creds encrypt --name=cluster_secret - \
    /etc/craton-hsm/creds/cluster_secret.cred
chmod 0600 /etc/craton-hsm/creds/cluster_secret.cred
```

The application reads the secret from `$CREDENTIALS_DIRECTORY/cluster_secret`.

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now craton-hsmd.service
systemctl status craton-hsmd.service
```

## Pattern B: Docker / OCI

Suitable for ephemeral, orchestrator-agnostic deployments. Build from the repo root.

### Dockerfile

```dockerfile
# syntax=docker/dockerfile:1.7
FROM rust:1.75-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake clang pkg-config libssl-dev golang \
 && rm -rf /var/lib/apt/lists/*
COPY . .
# craton-hsm-core must be vendored into the build context as a sibling dir
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin craton-hsmd --features fips && \
    cp /src/target/release/craton-hsmd /craton-hsmd && \
    strip /craton-hsmd

FROM gcr.io/distroless/cc-debian12:nonroot
# UID 65532 is the "nonroot" user baked into distroless
USER 65532:65532
COPY --from=build --chown=65532:65532 /craton-hsmd /usr/local/bin/craton-hsmd
EXPOSE 5696 8443 9443
ENTRYPOINT ["/usr/local/bin/craton-hsmd"]
CMD ["--config", "/etc/craton-hsm/config.toml"]
```

### Runtime

```bash
docker run -d --name craton-hsmd \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --security-opt=seccomp=default.json \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    -v /srv/craton-hsm/data:/var/lib/craton-hsm \
    -v /srv/craton-hsm/config:/etc/craton-hsm:ro \
    -e CRATON_HSM_CLUSTER_SECRET_FILE=/run/secrets/cluster_secret \
    -v /srv/craton-hsm/secrets/cluster_secret:/run/secrets/cluster_secret:ro \
    -p 5696:5696 -p 8443:8443 -p 9443:9443 \
    ghcr.io/craton-co/craton-hsmd:0.1.1
```

Host bind-mount `/srv/craton-hsm/data` must live on an encrypted filesystem. Do not bake secrets into the image.

## Pattern C: Kubernetes StatefulSet

Suitable for cloud-native, scale-out deployments on K8s 1.28+. Requires the PodSecurity admission plugin enforcing the `restricted` profile.

### Namespace & Policy

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: craton-hsm
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Secret (cluster_secret delivered via external secret manager)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: craton-hsm-cluster
  namespace: craton-hsm
type: Opaque
# data.cluster_secret is 32 random bytes, base64-encoded
```

In production source this from Vault / AWS Secrets Manager / ESO rather than a raw manifest.

### Services

```yaml
apiVersion: v1
kind: Service
metadata:
  name: craton-hsm-peers         # headless, for Raft peer DNS
  namespace: craton-hsm
spec:
  clusterIP: None
  selector:
    app: craton-hsmd
  ports:
    - name: raft
      port: 9443
      targetPort: 9443
---
apiVersion: v1
kind: Service
metadata:
  name: craton-hsm-kmip
  namespace: craton-hsm
spec:
  type: ClusterIP
  selector:
    app: craton-hsmd
  ports:
    - name: kmip
      port: 5696
      targetPort: 5696
```

### StatefulSet

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: craton-hsmd
  namespace: craton-hsm
spec:
  serviceName: craton-hsm-peers
  replicas: 3
  podManagementPolicy: Parallel
  selector:
    matchLabels:
      app: craton-hsmd
  template:
    metadata:
      labels:
        app: craton-hsmd
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile:
          type: RuntimeDefault
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: craton-hsmd
              topologyKey: kubernetes.io/hostname
      containers:
        - name: craton-hsmd
          image: ghcr.io/craton-co/craton-hsmd:0.1.1
          imagePullPolicy: IfNotPresent
          args: ["--config", "/etc/craton-hsm/config.toml"]
          ports:
            - name: kmip
              containerPort: 5696
            - name: admin
              containerPort: 8443
            - name: raft
              containerPort: 9443
          env:
            - name: CRATON_HSM_CLUSTER_SECRET_FILE
              value: /run/secrets/cluster/cluster_secret
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: "500m", memory: "512Mi" }
            limits:   { cpu: "2",    memory: "2Gi"   }
          volumeMounts:
            - { name: data,    mountPath: /var/lib/craton-hsm }
            - { name: config,  mountPath: /etc/craton-hsm, readOnly: true }
            - { name: cluster, mountPath: /run/secrets/cluster, readOnly: true }
            - { name: tmp,     mountPath: /tmp }
          livenessProbe:
            tcpSocket: { port: kmip }
            initialDelaySeconds: 20
            periodSeconds: 10
          readinessProbe:
            httpGet: { path: /readyz, port: admin, scheme: HTTPS }
            periodSeconds: 5
      volumes:
        - name: config
          configMap: { name: craton-hsm-config }
        - name: cluster
          secret:
            secretName: craton-hsm-cluster
            defaultMode: 0400
        - name: tmp
          emptyDir: { medium: Memory, sizeLimit: 64Mi }
  volumeClaimTemplates:
    - metadata: { name: data }
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: encrypted-ssd
        resources:
          requests:
            storage: 50Gi
```

### PDB and NetworkPolicy

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: craton-hsmd
  namespace: craton-hsm
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: craton-hsmd
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: craton-hsmd
  namespace: craton-hsm
spec:
  podSelector:
    matchLabels:
      app: craton-hsmd
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: { matchLabels: { app: craton-hsmd } }
      ports:
        - { port: 9443, protocol: TCP }  # Raft peers only
    - from:
        - namespaceSelector: { matchLabels: { craton.io/role: kmip-client } }
      ports:
        - { port: 5696, protocol: TCP }
  egress:
    - to:
        - podSelector: { matchLabels: { app: craton-hsmd } }
      ports:
        - { port: 9443, protocol: TCP }
    - to:
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
      ports:
        - { port: 53, protocol: UDP }
```

## Storage Sizing

| State | Typical Rate | Recommended Volume |
|-------|--------------|--------------------|
| Raft log | ~100 KB per committed op | 20 GiB with compaction every 10k entries |
| KMIP object store | ~4 KiB per wrapped key | 10 GiB for 1M keys; scale linearly |
| Audit log (local ring) | ~1 KiB per op | 5 GiB; forward to SIEM, do not retain locally |
| Total per replica | | 50 GiB baseline |

Use encrypted storage classes (LUKS on bare metal, `aws:kms`-backed EBS, CMEK-backed GCE PD).

## TLS Certificate Provisioning

- Internal CA issues server certs with SAN `craton-hsmd-{0,1,2}.craton-hsm-peers.craton-hsm.svc.cluster.local` plus the external KMIP FQDN.
- Minimum TLS 1.2 (1.3 preferred), per [HARDENING.md §6](HARDENING.md).
- Client certs for KMIP applications issued by the same CA; thumbprints enrolled in `craton-hsm-auth` certificate provider.
- Rotate every 90 days. `cert-manager` with a Vault/Venafi issuer is the recommended automation.
- Revocation: static CRLs mounted via ConfigMap or sidecar-fetched; see [HARDENING.md §3](HARDENING.md) and [OPERATIONS.md §3](OPERATIONS.md) for refresh procedure. HTTP CDP and OCSP are **not implemented** in `0.1.x` — see [SECURITY.md — Certificate revocation](SECURITY.md#craton-hsm-auth) for the authoritative statement.

## Post-Deploy Smoke Test

Run through this checklist on the first node of every new environment:

- [ ] `systemctl status craton-hsmd` / `kubectl get pods` shows all replicas `Running` / `Ready`.
- [ ] `ss -ltn` / `netstat` confirms listeners on 5696, 8443, 9443 bound to the expected interfaces.
- [ ] Cluster reports a single leader: `curl -sk https://<node>:8443/clusterz | jq .leader`.
- [ ] Raft log replicating: leader's `commit_index` advances and matches followers within 1s.
- [ ] `cluster_secret` loaded: logs contain no "running in insecure mode" warning.
- [ ] FIPS self-tests passed at startup (log line `fips self-test: PASS`).
- [ ] KMIP discovery: `kmipcli -c client.pem -k client.key -s <node>:5696 query` returns supported operations.
- [ ] Auth provider reachable: sample LDAP/OIDC login succeeds; rate limiter log entries appear after induced failures.
- [ ] CRL loaded and not expired: `/readyz` returns 200 and no "CRL expired" warning in logs.
- [ ] Audit log forwarding: a synthetic key-generation event appears in the SIEM within 30s.
- [ ] Backup path exercised: wrap-export a test key, store it, delete the live copy, restore, verify equality.
- [ ] Rolling restart tolerated: drain one replica, confirm quorum holds, rejoin, confirm catch-up.

Record the results in your change ticket before declaring the environment operational.

# Native agent protocol (DRAFT – NOT IMPLEMENTED)

This describes how a future Blackveil OS native agent (M9) will report to the Blackveil Security
web app. Nothing here exists in the kernel yet.

## Principles
- Outbound only: the device connects to the app over HTTPS; the device exposes no listening admin port.
- Enrolment: an admin creates a device in the web app and receives a one-time enrolment token.
  The device exchanges it for a per-device credential, stored hashed server-side. Tokens are never
  compiled into images.
- Least privilege: the agent runs as a dedicated non-root user and can only read health data and
  the audit log; remote commands are limited to an allowlist and every one is audit-logged.
- Revocation: the app can revoke a device; a rejected credential stops the agent.

## Messages (JSON over HTTPS)
| Direction | Message | Fields |
|---|---|---|
| device -> app | `enroll` | enrolment token, kernel version, hardware summary |
| device -> app | `heartbeat` | uptime, memory, task count, service states |
| device -> app | `audit` | batched audit events (sequence number, time, user, action, result) |
| app -> device | heartbeat response | `state`, optional allowlisted request |

Requires M8 (network stack + TLS) and M7 (users, audit log) first.

# Implementation Plan - Secure Authentication System for MAV Portal

## User Request
Implement a user authentication system for the MAV (Official Sales & Billing Portal) application including user registration, login, and logout functionality. Store user credentials securely using strong cryptographic password hashing with unique salt. Upon successful login, direct the user to the main dashboard. Integrate cleanly with existing dark/light themes.

## Security Threat Model

### Component Overview
The authentication module manages user identity for MAV Sales & Billing Portal (web application in `index.html` and mobile Android app in `MainActivity.kt`). It provides registration, credential verification, session lifecycle, and role-based tagging (Store Manager, Sales Executive, Cashier).

### Entry Points and Untrusted Inputs
| Entry Point | Type | Trusted? | Validation |
|---|---|---|---|
| Registration Form (Username, Name, Password) | UI Form Inputs | Untrusted | Sanitized alphanumeric username, length >= 3; password complexity (min 6 chars, mixed case/digit); HTML entity encoding |
| Login Form (Username, Password) | UI Form Inputs | Untrusted | Username/password lookup against cryptographically hashed records; rate-limiting / lockout indicators |
| Session Storage / Prefs | Client Storage | Semi-Trusted | Validated user session token, expiration timestamp, active user state |

### Trust Boundaries and Auth Assumptions
- **Authentication**: Salted cryptographic password hashing using PBKDF2-HMAC-SHA256 (Web Crypto API `crypto.subtle` in Web, `SecretKeyFactory` with PBKDF2 / SHA-256 + `SecureRandom` in Android).
- **Authorization**: Role verification (Store Manager vs Sales Associate) on UI actions.
- **Data Protection**: Never store plain-text passwords in `localStorage`, `SharedPreferences`, or logs.

### Sensitive Data Paths
| Data Type | Source | Destination | Protection |
|---|---|---|---|
| Plaintext Password | User Input | Cryptographic Hashing Routine | Memory-only, immediately hashed, never persisted |
| Password Salt & Hash | Key Derivation Function | Secure Storage | Hex-encoded salt (16 bytes random) + PBKDF2 hash (10,000+ iterations) |
| Session Credential | Login Auth Success | Session Store | Session token, cleared immediately on Logout |

### Privileged Actions
| Action | Location | Guard |
|---|---|---|
| View Sales Dashboard & Invoices | Dashboard Views | Guarded by active authenticated user session |
| Delete Sales Record / Reset Data | Dashboard Actions | Requires authenticated session (Store Manager) |
| Logout / Invalidate Session | Header User Menu | Clears session token, forces navigation to Auth screen |

### Priority Review Areas
1. Password hashing routines must use strong cryptographic algorithms and per-user random salts.
2. Input sanitization to prevent Stored / Reflected XSS when displaying user names and roles.
3. Proper session destruction on Logout preventing unauthorized back-navigation.

## Verification Plan

### Security Verification
- **Security Scan**: Inspect all newly created and modified files for common CWE vulnerabilities (CWE-256 Plaintext Storage of Passwords, CWE-79 XSS in user profile rendering, CWE-384 Session Fixation).
- **Security Audit**: Audit the implementation against the threat model. Document findings, dispositions, and remediations in `walkthrough.md` using the `generate-security-audit-report` skill.
- **PoC Verification**: Validate password hashing and session termination using the `run-poc` skill.

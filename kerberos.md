# Kerberos Protocol in AD

## Legend
- Kc - clients key - hashed password
- Ktgs - ticket-granting service's secret key
- Ks - service's secret key
- Kc-tgs - client-TGS session key
- Kc-s - client-server session key

## What is what?

### Key Distribution Center
Includes AS (Authentication Server) and TGS (Ticket-granting Server). 
It has:
- Kc
- Ktgs
- Ks
- Kc-tgs - after user authentication

### Client

Regular AD user. It has:

1. Initially:
    - Kc
2. After user authentication
    - Kc-tsg
    - TGT
3. After service authorization
    - Kc-s 
    - Client-server ticket

### SS (Service Server)
It has:

- Ks - hash of service account password
- K-cs (after service request)

## Accessing services
### User authentication

1. (Optional - pre-authentication) User sends timestamp encrypted with the password hash to prove identity.
2. User sends their ID to AS in plaintext.
3. AS looks it up in its database.
4. AS sends back two messages.
    - MessageA - {Kc-tgs}Kc
    - MessageB - {Kc-tgs, clientID, clientAddress, ticketExpDate}Ktgs - known as TGT (ticket-granting ticket, unique for each user)
5. Client decrypts MessageA with their password hash. However client can't decrypt the TGT.
6. Now client has Kc-tgs and TGT.

### Client Service Authorization
1. Client sends two messages to the TGS
    - MessageC - TGT + SPN
    - MessageD - {clientID, timestamp}Kc-tgs
2. TGS decrypts TGT and retrieves the Kc-tgs. This enables the TGS to decrypt MessageD, validate timestamp and compare clientID from both messages C and D. 
3. If they match, the TGS sends back two messages
    - MessageE - {Kc-s}Kc-tgs
    - MessageF - {Kc-s, clientID, clientAddress, ticketExpDate}Ks - service ticket
4. Client decrypts MessageE using Kc-tgs and retrieves Kc-s.

### Client Service Request
1. Client sends two messages to the SS (Service Server):
    - MessageF - service ticket
    - MessageG - {clientID, timestamp}Kc-s
2. Server decrypts MessageF and retrieves Kc-s. It then decrypts MessageF, validates timestamp and compares clientID from messages F and G.
3. Server encrypts the timestamp (incremented in version 4, not necesseraly in version 5) from MessageG and sends it back to the client to prove its identity and confirm willingness to serve the client.
4. Client decrypts and validates the timestamp. If it's corrent, client starts issuing requests to the server.

# Attacking Kerberos
## Kerberoasting
### Service ticket
#### Requirements
Domain user account compromised
#### Description
1. Dump SPNs of services in a domain.
2. Request TGT for the compromised user.
3. Using the TGT ticket, request service ticket for the demanded service. 
4. Service ticket is encrypted using service account's hash.
5. Crack it offline.
#### Tools
- Impacket
```bash
./GetUserSPNs.py -dc-ip domain controller -request domain/user:password
```
- Rubeus
```bash
./Rubeus.exe kerberoast
```
- Hydra mode `13100`

### AS-REP roasting
#### Requirements
Domain user account compromised
#### Description
1. Find all users with disables pre-authentication.
2. Request a TGT for them.
3. Alongside TGTs you receive session keys encrypted with users' hashes.
4. Crack them offline. 
#### Tools
- Impacket
```bash
./GetNPUsers.py domain/user -no-pass
```
- Rubeus
```bash
./Rubeus.exe asreproast
```
- Hydra mode `18200`

# Limitations (current)
- Hub-and-spoke: the gateway sees decrypted inter-client traffic. Full-mesh peer IPsec is a separate future architecture.
- IPv4 only. IPv6 is neither tunnelled nor firewalled (the wizard warns if global IPv6 is present).
- IPsec does not protect ARP; broadcast/multicast (e.g. mDNS) are not forced through tunnels and are not blocked by the client policy.
- Connecting to a peer by its **LAN address** is blocked by design; only overlay names/addresses work. Inbound SSH *to* a client from LAN peers is dropped.
- Enrollment/renewal talk to the CA over the physical LAN (TLS with a pinned root); this is the one deliberate plaintext-network exception, plus IKE.
- Revocation: gateway identity removal is immediate; CA revocation is passive; CRL consumption by strongSwan is not wired up yet. The certificate serial is not
  collected automatically (use `lanseal set-serial`); an enrollment API will fix this in the Go port.
- Per-device ACLs inside the overlay do not exist yet: any enrolled device can reach any other on any port.
- Windows, Android, Go CLI, backup/restore and the full interoperability test report are not implemented yet; Windows will need native-IKEv2 hardening, and Android needs
  the strongSwan app because key/route options differ per device (an imported PKCS#12 key is software-held, **not** Keystore/hardware-backed).

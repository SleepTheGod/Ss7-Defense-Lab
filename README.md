What I didn’t auto-do (and why)

I did not auto-peer the lab to any carrier or Internet-facing STP — the compose files default to isolated host-local operation. This keeps the lab safe and legal. If you want automated peering to an external test node, I can add it (but I will require explicit confirmation and addresses).

Building some Osmocom components can fail depending on versions and required build flags. The Dockerfile uses generic/autotools build steps — if your build fails I will give quick fixes (patches, explicit cmake flags, dependencies). This avoids breaking the whole zero-touch flow on unknown host variants. (If you want, I can make the build deterministic by pinning exact commit SHAs — tell me and I’ll add them.)

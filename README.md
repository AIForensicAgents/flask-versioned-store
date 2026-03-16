┌─────────────────────────────────────────────────────────────────┐
│                         CLIENTS                                 │
│              (curl, SDKs, browsers, CI/CD)                      │
└──────────────────────┬──────────────────────────────────────────┘
                       │  HTTPS (Bearer Token)
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FLASK APPLICATION                            │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ POST     │  │ POST     │  │ POST     │  │ POST          │  │
│  │ /token   │  │ /write   │  │ /read    │  │ /serve        │  │
│  │          │  │          │  │          │  │               │  │
│  │ Generate │  │ Store    │  │ Retrieve │  │ Serve content │  │
│  │ auth     │  │ versioned│  │ by key & │  │ with MIME     │  │
│  │ tokens   │  │ data     │  │ version  │  │ type          │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬────────┘  │
│       │              │              │               │           │
│       ▼              ▼              ▼               ▼           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              AUTH & OWNERSHIP MIDDLEWARE                 │   │
│  │         (Token validation + user scoping)               │   │
│  └────────────────────────┬────────────────────────────────┘   │
│                           │                                     │
│                           ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │               VERSIONED STORE ENGINE                    │   │
│  │                                                         │   │
│  │   key → [ v0: {value, ts}, v1: {value, ts}, ... ]      │   │
│  └────────────────────────┬────────────────────────────────┘   │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            │  Read / Write
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FILESYSTEM PERSISTENCE                        │
│                                                                 │
│   ./data/                                                       │
│   ├── tokens.json            # user → hashed token mapping      │
│   └── store/                                                    │
│       ├── <user_a>/                                             │
│       │   ├── config.json    # versioned values for "config"    │
│       │   └── template.json  # versioned values for "template"  │
│       └── <user_b>/                                             │
│           └── settings.json                                     │
└─────────────────────────────────────────────────────────────────┘
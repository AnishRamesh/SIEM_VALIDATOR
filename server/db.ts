import fs from 'fs/promises';
import path from 'path';
import { MongoClient, Db } from 'mongodb';
import { CorrelationRule, SiemConfig, TacticCoverageSnapshot, ValidationState } from '../src/types';

const DATA_DIR = path.resolve(process.cwd(), 'data');

const CONFIG_FILE = path.join(DATA_DIR, 'siem_configs.json');
const RULES_FILE = path.join(DATA_DIR, 'correlation_rules.json');
const SNAPSHOTS_FILE = path.join(DATA_DIR, 'tactic_coverage_snapshots.json');

// Helper to ensure data directory and files exist with initial mock data
async function ensureDbInitialized() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (e) {
    // Ignore if exists
  }

  // Define initial configs
  try {
    await fs.access(CONFIG_FILE);
  } catch {
    const initialConfig: SiemConfig[] = [
      {
        _id: 'config_primary',
        platformType: 'Palo Alto XSIAM',
        apiEndpoint: 'https://api-wipprd.xdr.in.paloaltonetworks.com',
        apiId: '425',
        apiPassphraseHash: '********',
        lastSyncedAt: new Date(Date.now() - 4 * 60 * 1000).toISOString() // 4 minutes ago
      }
    ];
    await fs.writeFile(CONFIG_FILE, JSON.stringify(initialConfig, null, 2), 'utf-8');
  }

  // Define initial correlation rules
  let deservesSeeding = false;
  try {
    const rawContent = await fs.readFile(RULES_FILE, 'utf-8');
    const existingRules = JSON.parse(rawContent);
    if (!Array.isArray(existingRules) || existingRules.length === 0) {
      deservesSeeding = true;
    }
  } catch {
    deservesSeeding = true;
  }

  if (deservesSeeding) {
    const initialRules: CorrelationRule[] = [
      {
        _id: 'rule_1',
        ruleId: 'RULE-001',
        ruleName: 'UC - Credential Dumping via LSASS Memory Access',
        siemSource: 'xyzcomp',
        existingTid: 'T1003.001',
        mappedTechniqueName: 'OS Credential Dumping: LSASS Memory',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Verified memory footprint indicators; rule alert triggered accurately.',
        dateAdded: '2026-05-15T10:00:00Z',
        lastUpdated: '2026-06-02T15:00:00Z'
      },
      {
        _id: 'rule_2',
        ruleId: 'RULE-002',
        ruleName: 'UC - Suspicious Encoded PowerShell Execution in Environment',
        siemSource: 'xyzcomp',
        existingTid: 'T1059.001',
        mappedTechniqueName: 'Command and Scripting Interpreter: PowerShell',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Whitelisted known deployment scripts; remaining outputs malicious.',
        dateAdded: '2026-05-18T14:30:00Z',
        lastUpdated: '2026-06-02T14:40:00Z'
      },
      {
        _id: 'rule_3',
        ruleId: 'RULE-003',
        ruleName: 'UAT - Suspicious Registry Run Keys Persistence Added',
        siemSource: 'xyzcomp',
        existingTid: 'T1547.001',
        mappedTechniqueName: 'Boot or Logon Autostart Execution: Registry Run Keys',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Auto-audited registry hive modifications; high-signal behavior.',
        dateAdded: '2026-05-20T08:15:00Z',
        lastUpdated: '2026-06-02T12:00:00Z'
      },
      {
        _id: 'rule_4',
        ruleId: 'RULE-004',
        ruleName: 'threat - RDP Tunneling over SSH to Internal Resources',
        siemSource: 'xyzcomp',
        existingTid: 'T1021.001',
        mappedTechniqueName: 'Remote Services: Remote Desktop Protocol',
        suggestedTid: 'T1090.002',
        confidenceScore: null,
        validationState: 'NEEDS_FIX',
        actionsTaken: 'Investigating tunneling proxies; existing mapping is too broad.',
        dateAdded: '2026-05-22T19:00:00Z',
        lastUpdated: '2026-06-02T11:00:00Z'
      },
      {
        _id: 'rule_5',
        ruleId: 'RULE-005',
        ruleName: 'UAT - LSASS Process Memory Dump Signal',
        siemSource: 'xyzcomp',
        existingTid: 'T1003.001',
        mappedTechniqueName: 'OS Credential Dumping: LSASS Memory',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Matches standard Mimikatz activity signature.',
        dateAdded: '2026-05-24T11:20:00Z',
        lastUpdated: '2026-06-02T14:30:00Z'
      },
      {
        _id: 'rule_6',
        ruleId: 'RULE-006',
        ruleName: 'threat - WMI Process Spawned Suspicious Shell Terminal',
        siemSource: 'xyzcomp',
        existingTid: 'T1047',
        mappedTechniqueName: 'Windows Management Instrumentation',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Flagged cmd.exe spawning from WmiPrvSE.exe context.',
        dateAdded: '2026-05-25T16:00:00Z',
        lastUpdated: '2026-06-01T09:00:00Z'
      },
      {
        _id: 'rule_7',
        ruleId: 'RULE-007',
        ruleName: 'Multiple Domain Admin Logins from Single Workstation',
        siemSource: 'xyzcomp',
        existingTid: 'T1078.002',
        mappedTechniqueName: 'Valid Accounts: Domain Accounts',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'UNASSIGNED',
        actionsTaken: 'Awaiting administrator behavior confirmation.',
        dateAdded: '2026-05-28T13:45:00Z',
        lastUpdated: '2026-06-02T14:00:00Z'
      },
      {
        _id: 'rule_8',
        ruleId: 'RULE-008',
        ruleName: 'Active Scanning Port Probe Activity',
        siemSource: 'xyzcomp',
        existingTid: 'T1046',
        mappedTechniqueName: 'Network Service Discovery',
        suggestedTid: 'T1595',
        confidenceScore: null,
        validationState: 'NEEDS_FIX',
        actionsTaken: 'T-ID points to post-compromise discovery, but logs show external scanning.',
        dateAdded: '2026-05-29T21:10:00Z',
        lastUpdated: '2026-06-02T15:20:00Z'
      },
      {
        _id: 'rule_9',
        ruleId: 'RULE-009',
        ruleName: 'Acquisition of Penetration Testing Frameworks via Torrent',
        siemSource: 'xyzcomp',
        existingTid: 'T1588.002',
        mappedTechniqueName: 'Obtain Capabilities: Tools',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Valid tool download warning on local developer subnet.',
        dateAdded: '2026-05-30T10:15:00Z',
        lastUpdated: '2026-06-02T10:00:00Z'
      },
      {
        _id: 'rule_10',
        ruleId: 'RULE-010',
        ruleName: 'Brute Force Attack on Admin Logins Endpoint',
        siemSource: 'xyzcomp',
        existingTid: 'T1110',
        mappedTechniqueName: 'Brute Force',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'High threshold RDP failed attempts block successfully analyzed.',
        dateAdded: '2026-06-01T04:22:00Z',
        lastUpdated: '2026-06-02T15:10:00Z'
      },
      {
        _id: 'rule_11',
        ruleId: 'RULE-011',
        ruleName: 'Unrecognized Lateral Database Authentication Swarm',
        siemSource: 'xyzcomp',
        existingTid: '',
        mappedTechniqueName: 'Missing Mapping',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'UNASSIGNED',
        actionsTaken: 'Rule has been loaded without metadata context or MITRE assignment; triage required.',
        dateAdded: '2026-06-02T09:12:00Z',
        lastUpdated: '2026-06-03T10:00:00Z'
      },
      {
        _id: 'rule_12',
        ruleId: 'RULE-012',
        ruleName: 'Suspicious External Endpoint Proxy Connection Detect',
        siemSource: 'xyzcomp',
        existingTid: 'UNMAPPED',
        mappedTechniqueName: 'Unmapped Technique',
        suggestedTid: 'T1090.003',
        confidenceScore: null,
        validationState: 'NEEDS_FIX',
        actionsTaken: 'Proxy traffic matching external tunnel; lacks definitive post-compromise T-ID mapping.',
        dateAdded: '2026-06-02T11:45:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_13',
        ruleId: 'RULE-013',
        ruleName: 'Uncommonly Scheduled Task Registered by System Account',
        siemSource: 'xyzcomp',
        existingTid: 'T1053.005',
        mappedTechniqueName: 'Scheduled Task/Job: Scheduled Task',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Identified non-standard background task registered in Windows Task Scheduler.',
        dateAdded: '2026-06-02T14:00:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_14',
        ruleId: 'RULE-014',
        ruleName: 'Defense Evasion through Security Event Audit Log Clearing',
        siemSource: 'xyzcomp',
        existingTid: 'T1070.001',
        mappedTechniqueName: 'Indicator Removal: Clear Windows Event Logs',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Flags calling of wevtutil to truncate security logs.',
        dateAdded: '2026-06-02T15:30:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_15',
        ruleId: 'RULE-015',
        ruleName: 'Evasive Process Spawned Outside Standard Windows Directories',
        siemSource: 'xyzcomp',
        existingTid: 'T1204.002',
        mappedTechniqueName: 'User Execution: Malicious File',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'UNASSIGNED',
        actionsTaken: 'Executable path is located within %TEMP% directory.',
        dateAdded: '2026-06-03T01:10:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_16',
        ruleId: 'RULE-016',
        ruleName: 'Potential Kerberoasting Activity Against Windows Domain Controller',
        siemSource: 'xyzcomp',
        existingTid: 'T1558.003',
        mappedTechniqueName: 'Steal or Abuse Credentials: Kerberoasting',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Large volume of RC4-hashed Kerberos service ticket requests.',
        dateAdded: '2026-06-03T02:45:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_17',
        ruleId: 'RULE-017',
        ruleName: 'WinRM Administrative Session Initiated for Lateral Movement',
        siemSource: 'xyzcomp',
        existingTid: 'T1021.006',
        mappedTechniqueName: 'Remote Services: Windows Remote Management',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Inbound WS-Management protocol connection detected from developer node.',
        dateAdded: '2026-06-03T04:15:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_18',
        ruleId: 'RULE-018',
        ruleName: 'Inhibit System Recovery Attempted via Vssadmin Utility',
        siemSource: 'xyzcomp',
        existingTid: 'T1490',
        mappedTechniqueName: 'Inhibit System Recovery',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Detected deletion of volume shadow storage files to disable system rollbacks.',
        dateAdded: '2026-06-03T05:50:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_19',
        ruleId: 'RULE-019',
        ruleName: 'Rundll32 Invoked with Untrusted or Non-Standard System Library',
        siemSource: 'xyzcomp',
        existingTid: 'T1218.011',
        mappedTechniqueName: 'System Binary Proxy Execution: Rundll32',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'UNASSIGNED',
        actionsTaken: 'Rundll32 calling non-standard DLL in AppData context.',
        dateAdded: '2026-06-03T06:20:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_20',
        ruleId: 'RULE-020',
        ruleName: 'Suspicious Local Admin Username Creation on Isolated Host',
        siemSource: 'xyzcomp',
        existingTid: 'T1136.001',
        mappedTechniqueName: 'Create Account: Local Account',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Flags creation of a localized administrative user command line prompt.',
        dateAdded: '2026-06-03T07:15:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_21',
        ruleId: 'RULE-021',
        ruleName: 'DNS Tunneling Payload Exchange with External Server Signature',
        siemSource: 'xyzcomp',
        existingTid: 'T1071.004',
        mappedTechniqueName: 'Application Layer Protocol: DNS',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Flags high frequency TXT record requests carrying payloads.',
        dateAdded: '2026-06-03T08:00:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_22',
        ruleId: 'RULE-022',
        ruleName: 'Process Hollowing in Standard System Process Core Context',
        siemSource: 'xyzcomp',
        existingTid: 'T1055.012',
        mappedTechniqueName: 'Process Injection: Process Hollowing',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'UNASSIGNED',
        actionsTaken: 'Flags suspicious process spawning in suspended state followed by memory injection.',
        dateAdded: '2026-06-03T09:30:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_23',
        ruleId: 'RULE-023',
        ruleName: 'Massive Web Shell Execution Pattern on Enterprise IIS Server',
        siemSource: 'xyzcomp',
        existingTid: 'T1505.003',
        mappedTechniqueName: 'Server Software Component: Web Shell',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Flags unexpected .aspx files executing operating system level shell commands.',
        dateAdded: '2026-06-03T10:15:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      },
      {
        _id: 'rule_24',
        ruleId: 'RULE-024',
        ruleName: 'Data Compressed or Archived Prior to Remote Transfer',
        siemSource: 'xyzcomp',
        existingTid: 'T1560.001',
        mappedTechniqueName: 'Archive Collected Data: Archive via Utility',
        suggestedTid: null,
        confidenceScore: null,
        validationState: 'CORRECT',
        actionsTaken: 'Detected execution of zip/7z compression binary targeting sensitive databases.',
        dateAdded: '2026-06-03T11:00:00Z',
        lastUpdated: '2026-06-03T10:15:00Z'
      }
    ];

    await fs.writeFile(RULES_FILE, JSON.stringify(initialRules, null, 2), 'utf-8');
  }

  // Define initial monthly snapshots for comparison
  try {
    await fs.access(SNAPSHOTS_FILE);
  } catch {
    const initialSnapshots: TacticCoverageSnapshot[] = [
      {
        _id: 'snapshot_prev',
        snapshotMonth: '2026-05',
        tactics: {
          'TA0043': { currentMonth: 82, previousMonth: 78 }, // Reconnaissance
          'TA0042': { currentMonth: 91, previousMonth: 88 }, // Resource Dev
          'TA0001': { currentMonth: 45, previousMonth: 40 }, // Initial Access
          'TA0002': { currentMonth: 64, previousMonth: 60 }, // Execution
          'TA0003': { currentMonth: 40, previousMonth: 38 }, // Persistence
          'TA0004': { currentMonth: 70, previousMonth: 65 }, // Privilege Escalation
          'TA0005': { currentMonth: 48, previousMonth: 45 }, // Defence Impairment
          'TA0006': { currentMonth: 78, previousMonth: 72 }, // Credential Access
          'TA0007': { currentMonth: 52, previousMonth: 50 }, // Discovery
          'TA0008': { currentMonth: 38, previousMonth: 35 }, // Lateral Movement
          'TA0009': { currentMonth: 62, previousMonth: 58 }, // Collection
          'TA0011': { currentMonth: 75, previousMonth: 70 }, // Command and Control
          'TA0010': { currentMonth: 42, previousMonth: 40 }, // Exfiltration
          'TA0108': { currentMonth: 50, previousMonth: 45 }, // Stealth
          'TA0040': { currentMonth: 68, previousMonth: 62 }  // Impact
        }
      }
    ];
    await fs.writeFile(SNAPSHOTS_FILE, JSON.stringify(initialSnapshots, null, 2), 'utf-8');
  }
}

// Read database helper
async function readCollection<T>(filePath: string): Promise<T[]> {
  await ensureDbInitialized();
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content) as T[];
  } catch (error) {
    console.error(`Error reading database file at ${filePath}`, error);
    return [];
  }
}

// Write database helper
async function writeCollection<T>(filePath: string, data: T[]): Promise<void> {
  await ensureDbInitialized();
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

// --- MongoDB State Management ---
let mongoClient: MongoClient | null = null;
let mongoDb: Db | null = null;
let isMongoConnected = false;
let mongoConnectionError = '';

export async function connectToMongo(): Promise<{ connected: boolean; message: string }> {
  if (isMongoConnected && mongoDb) {
    return { connected: true, message: 'Already connected to MongoDB' };
  }
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/anishdb';
  try {
    mongoClient = new MongoClient(mongoUri, { connectTimeoutMS: 2500, socketTimeoutMS: 2500 });
    await mongoClient.connect();
    mongoDb = mongoClient.db('anishdb');
    isMongoConnected = true;
    mongoConnectionError = '';
    console.log('Successfully connected to MongoDB database: anishdb');
    
    // Seed database if empty so standard data shows up immediately
    await seedMongoIfEmpty();
    
    return { connected: true, message: 'Connected to MongoDB: anishdb' };
  } catch (err: any) {
    isMongoConnected = false;
    mongoDb = null;
    mongoConnectionError = err.message;
    console.warn(`MongoDB connection to ${mongoUri} failed. Falling back to local local-disk JSON storage:`, err.message);
    return { connected: false, message: `MongoDB offline. Using local files. Error: ${err.message}` };
  }
}

async function seedMongoIfEmpty() {
  if (!mongoDb) return;
  try {
    // 1. Seed siem_configs
    const configCol = mongoDb.collection('siem_configs');
    const configCount = await configCol.countDocuments();
    if (configCount === 0) {
      const parentConfigs = await readCollection<SiemConfig>(CONFIG_FILE);
      if (parentConfigs.length > 0) {
        await configCol.insertMany(parentConfigs as any[]);
        console.log(`Seeded ${parentConfigs.length} configurations to MongoDB`);
      }
    }

    // 2. Seed correlation_rules
    const rulesCol = mongoDb.collection('correlation_rules');
    const rulesCount = await rulesCol.countDocuments();
    if (rulesCount === 0) {
      const parentRules = await readCollection<CorrelationRule>(RULES_FILE);
      if (parentRules.length > 0) {
        await rulesCol.insertMany(parentRules as any[]);
        console.log(`Seeded ${parentRules.length} correlation rules to MongoDB`);
      }
    }

    // 3. Seed tactic_coverage_snapshots
    const snapCol = mongoDb.collection('tactic_coverage_snapshots');
    const snapCount = await snapCol.countDocuments();
    if (snapCount === 0) {
      const parentSnaps = await readCollection<TacticCoverageSnapshot>(SNAPSHOTS_FILE);
      if (parentSnaps.length > 0) {
        await snapCol.insertMany(parentSnaps as any[]);
        console.log(`Seeded ${parentSnaps.length} snapshots to MongoDB`);
      }
    }
  } catch (err) {
    console.error('Failed to seed MongoDB empty collections:', err);
  }
}

export const db = {
  // Query status
  getMongoStatus(): { connected: boolean; dbName: string; error?: string } {
    return {
      connected: isMongoConnected,
      dbName: 'anishdb',
      error: mongoConnectionError || undefined
    };
  },

  // --- SiemConfig Collection ---
  async getSiemConfigs(): Promise<SiemConfig[]> {
    if (isMongoConnected && mongoDb) {
      try {
        const items = await mongoDb.collection('siem_configs').find({}).toArray();
        return items as unknown as SiemConfig[];
      } catch (err) {
        console.error('Mongo error getting siem configs, fallback to file:', err);
      }
    }
    return readCollection<SiemConfig>(CONFIG_FILE);
  },

  async saveSiemConfig(config: SiemConfig): Promise<SiemConfig> {
    if (isMongoConnected && mongoDb) {
      try {
        await mongoDb.collection('siem_configs').updateOne(
          { _id: config._id as any },
          { $set: config as any },
          { upsert: true }
        );
        return config;
      } catch (err) {
        console.error('Mongo error saving siem config, saving locally too:', err);
      }
    }
    // Save locally as fallback/cache
    const configs = await readCollection<SiemConfig>(CONFIG_FILE);
    const idx = configs.findIndex(c => c._id === config._id);
    if (idx >= 0) {
      configs[idx] = config;
    } else {
      configs.push(config);
    }
    await writeCollection<SiemConfig>(CONFIG_FILE, configs);
    return config;
  },

  // --- CorrelationRule Collection ---
  async getCorrelationRules(): Promise<CorrelationRule[]> {
    if (isMongoConnected && mongoDb) {
      try {
        const items = await mongoDb.collection('correlation_rules').find({}).toArray();
        return items as unknown as CorrelationRule[];
      } catch (err) {
        console.error('Mongo error getting correlation rules, fallback to file:', err);
      }
    }
    return readCollection<CorrelationRule>(RULES_FILE);
  },

  async saveAllCorrelationRules(rules: CorrelationRule[]): Promise<void> {
    if (isMongoConnected && mongoDb) {
      try {
        const col = mongoDb.collection('correlation_rules');
        // Overwrite standard list of loaded / API pull rules
        await col.deleteMany({});
        if (rules.length > 0) {
          await col.insertMany(rules as any[]);
        }
        return;
      } catch (err) {
        console.error('Mongo error overriding correlation rules list:', err);
      }
    }
    await writeCollection<CorrelationRule>(RULES_FILE, rules);
  },

  async saveCorrelationRule(rule: CorrelationRule): Promise<CorrelationRule> {
    const now = new Date().toISOString();
    rule.lastUpdated = now;
    if (!rule.dateAdded) {
      rule.dateAdded = now;
    }

    if (isMongoConnected && mongoDb) {
      try {
        await mongoDb.collection('correlation_rules').updateOne(
          { _id: rule._id as any },
          { $set: rule as any },
          { upsert: true }
        );
        return rule;
      } catch (err) {
        console.error('Mongo error saving single correlation rule, falling back locally:', err);
      }
    }

    const rules = await readCollection<CorrelationRule>(RULES_FILE);
    const idx = rules.findIndex(r => r._id === rule._id);
    if (idx >= 0) {
      rules[idx] = rule;
    } else {
      rules.push(rule);
    }
    await writeCollection<CorrelationRule>(RULES_FILE, rules);
    return rule;
  },

  async deleteCorrelationRule(id: string): Promise<boolean> {
    if (isMongoConnected && mongoDb) {
      try {
        const result = await mongoDb.collection('correlation_rules').deleteOne({ _id: id as any });
        return (result.deletedCount ?? 0) > 0;
      } catch (err) {
        console.error('Mongo error deleting correlation rule, falling back locally:', err);
      }
    }

    const rules = await readCollection<CorrelationRule>(RULES_FILE);
    const filtered = rules.filter(r => r._id !== id);
    if (filtered.length === rules.length) return false;
    await writeCollection<CorrelationRule>(RULES_FILE, filtered);
    return true;
  },

  // --- TacticCoverageSnapshot Collection ---
  async getSnapshots(): Promise<TacticCoverageSnapshot[]> {
    if (isMongoConnected && mongoDb) {
      try {
        const items = await mongoDb.collection('tactic_coverage_snapshots').find({}).toArray();
        return items as unknown as TacticCoverageSnapshot[];
      } catch (err) {
        console.error('Mongo error getting snapshots, falling back locally:', err);
      }
    }
    return readCollection<TacticCoverageSnapshot>(SNAPSHOTS_FILE);
  },

  async saveSnapshot(snapshot: TacticCoverageSnapshot): Promise<TacticCoverageSnapshot> {
    if (isMongoConnected && mongoDb) {
      try {
        await mongoDb.collection('tactic_coverage_snapshots').updateOne(
          { _id: snapshot._id as any },
          { $set: snapshot as any },
          { upsert: true }
        );
        return snapshot;
      } catch (err) {
        console.error('Mongo error saving snapshot, falling back locally:', err);
      }
    }

    const snapshots = await readCollection<TacticCoverageSnapshot>(SNAPSHOTS_FILE);
    const idx = snapshots.findIndex(s => s._id === snapshot._id);
    if (idx >= 0) {
      snapshots[idx] = snapshot;
    } else {
      snapshots.push(snapshot);
    }
    await writeCollection<TacticCoverageSnapshot>(SNAPSHOTS_FILE, snapshots);
    return snapshot;
  },
};

// Static definition of tactics, techniques, and mapping constraints for MITRE ATT&CK v19.1
// Static definition of tactics, techniques, and mapping constraints for MITRE ATT&CK v19.1
// Static definition of tactics, techniques, and mapping constraints for MITRE ATT&CK v19.1
// Static definition of tactics, techniques, and mapping constraints for MITRE ATT&CK v19.1
// Static definition of tactics, techniques, and mapping constraints for MITRE ATT&CK v19.1
// Static definition of tactics, techniques, and mapping constraints for MITRE ATT&CK v19.1
// Static definition of tactics, techniques, and mapping constraints for MITRE ATT&CK v19.1
export const MITRE_ATTACK_DB = [
  {
    tacticId: 'TA0043',
    name: 'Reconnaissance',
    shortName: 'RECON',
    techniques: [
      {
        tid: 'T1595',
        name: 'Active Scanning',
        subTechniques: [
          { tid: 'T1595.001', name: 'Scanning IP Blocks' },
          { tid: 'T1595.002', name: 'Vulnerability Scanning' },
          { tid: 'T1595.003', name: 'Wordlist Scanning' }
        ]
      },
      {
        tid: 'T1592',
        name: 'Gather Victim Host Information',
        subTechniques: [
          { tid: 'T1592.001', name: 'Hardware' },
          { tid: 'T1592.002', name: 'Software' },
          { tid: 'T1592.003', name: 'Firmware' },
          { tid: 'T1592.004', name: 'Client Configurations' }
        ]
      },
      {
        tid: 'T1589',
        name: 'Gather Victim Identity Information',
        subTechniques: [
          { tid: 'T1589.001', name: 'Credentials' },
          { tid: 'T1589.002', name: 'Email Addresses' },
          { tid: 'T1589.003', name: 'Employee Names' }
        ]
      },
      {
        tid: 'T1590',
        name: 'Gather Victim Network Information',
        subTechniques: [
          { tid: 'T1590.001', name: 'Domain Properties' },
          { tid: 'T1590.002', name: 'DNS' },
          { tid: 'T1590.003', name: 'Network Trust Dependencies' },
          { tid: 'T1590.004', name: 'Network Topology' },
          { tid: 'T1590.005', name: 'IP Addresses' },
          { tid: 'T1590.006', name: 'Network Security Appliances' }
        ]
      },
      {
        tid: 'T1591',
        name: 'Gather Victim Org Information',
        subTechniques: [
          { tid: 'T1591.001', name: 'Determine Physical Locations' },
          { tid: 'T1591.002', name: 'Business Relationships' },
          { tid: 'T1591.003', name: 'Identify Business Tempo' },
          { tid: 'T1591.004', name: 'Identify Roles' }
        ]
      },
      {
        tid: 'T1598',
        name: 'Phishing for Information',
        subTechniques: [
          { tid: 'T1598.001', name: 'Spearphishing Service' },
          { tid: 'T1598.002', name: 'Spearphishing Attachment' },
          { tid: 'T1598.003', name: 'Spearphishing Link' },
          { tid: 'T1598.004', name: 'Spearphishing Voice' }
        ]
      },
      {
        tid: 'T1682',
        name: 'Query Public AI Services'
      },
      {
        tid: 'T1597',
        name: 'Search Closed Sources',
        subTechniques: [
          { tid: 'T1597.001', name: 'Threat Intel Vendors' },
          { tid: 'T1597.002', name: 'Purchase Technical Data' }
        ]
      },
      {
        tid: 'T1596',
        name: 'Search Open Technical Databases',
        subTechniques: [
          { tid: 'T1596.001', name: 'DNS/Passive DNS' },
          { tid: 'T1596.002', name: 'WHOIS' },
          { tid: 'T1596.003', name: 'Digital Certificates' },
          { tid: 'T1596.004', name: 'CDNs' },
          { tid: 'T1596.005', name: 'Scan Databases' }
        ]
      },
      {
        tid: 'T1593',
        name: 'Search Open Websites/Domains',
        subTechniques: [
          { tid: 'T1593.001', name: 'Social Media' },
          { tid: 'T1593.002', name: 'Search Engines' },
          { tid: 'T1593.003', name: 'Code Repositories' }
        ]
      },
      {
        tid: 'T1681',
        name: 'Search Threat Vendor Data'
      },
      {
        tid: 'T1594',
        name: 'Search Victim-Owned Websites'
      }
    ]
  },
  {
    tacticId: 'TA0042',
    name: 'Resource Development',
    shortName: 'RES DEV',
    techniques: [
      {
        tid: 'T1588',
        name: 'Obtain Capabilities',
        subTechniques: [
          { tid: 'T1588.001', name: 'Malware' },
          { tid: 'T1588.002', name: 'Tool' },
          { tid: 'T1588.003', name: 'Exploits' },
          { tid: 'T1588.004', name: 'Cryptographic Certificates' },
          { tid: 'T1588.005', name: 'Exploitation Material' },
          { tid: 'T1588.006', name: 'Vulnerabilities' }
        ]
      },
      {
        tid: 'T1583',
        name: 'Acquire Infrastructure',
        subTechniques: [
          { tid: 'T1583.001', name: 'Domains' },
          { tid: 'T1583.002', name: 'DNS Server' },
          { tid: 'T1583.003', name: 'Virtual Private Servers' },
          { tid: 'T1583.004', name: 'Server' },
          { tid: 'T1583.005', name: 'Botnet' },
          { tid: 'T1583.006', name: 'Web Services' },
          { tid: 'T1583.007', name: 'Serverless' },
          { tid: 'T1583.008', name: 'Static IP Addresses' }
        ]
      },
      {
        tid: 'T1584',
        name: 'Compromise Infrastructure',
        subTechniques: [
          { tid: 'T1584.001', name: 'Domains' },
          { tid: 'T1584.002', name: 'DNS Server' },
          { tid: 'T1584.003', name: 'Virtual Private Servers' },
          { tid: 'T1584.004', name: 'Server' },
          { tid: 'T1584.005', name: 'Botnet' },
          { tid: 'T1584.006', name: 'Web Services' },
          { tid: 'T1584.007', name: 'Serverless' },
          { tid: 'T1584.008', name: 'Router' }
        ]
      },
      {
        tid: 'T1587',
        name: 'Develop Capabilities',
        subTechniques: [
          { tid: 'T1587.001', name: 'Malware' },
          { tid: 'T1587.002', name: 'Tool' },
          { tid: 'T1587.003', name: 'Exploits' },
          { tid: 'T1587.004', name: 'Cryptographic Certificates' },
          { tid: 'T1587.005', name: 'Infrastructure' }
        ]
      },
      {
        tid: 'T1608',
        name: 'Stage Capabilities',
        subTechniques: [
          { tid: 'T1608.001', name: 'Upload Malware' },
          { tid: 'T1608.002', name: 'Upload Tool' },
          { tid: 'T1608.003', name: 'Install Certificates' },
          { tid: 'T1608.004', name: 'Drive-by Target' },
          { tid: 'T1608.005', name: 'Link Target' },
          { tid: 'T1608.006', name: 'SEO Poisoning' }
        ]
      },
      {
        tid: 'T1585',
        name: 'Compromise Accounts',
        subTechniques: [
          { tid: 'T1585.001', name: 'Social Media Accounts' },
          { tid: 'T1585.002', name: 'Email Accounts' },
          { tid: 'T1585.003', name: 'Cloud Accounts' }
        ]
      },
      {
        tid: 'T1586',
        name: 'Manage Accounts',
        subTechniques: [
          { tid: 'T1586.001', name: 'Social Media Accounts' },
          { tid: 'T1586.002', name: 'Email Accounts' },
          { tid: 'T1586.003', name: 'Cloud Accounts' }
        ]
      },
      {
        tid: 'T1609',
        name: 'Establish Cloud Repositories'
      },
      {
        tid: 'T1610',
        name: 'Prepare Virtual Execution Environments'
      }
    ]
  },
  {
    tacticId: 'TA0001',
    name: 'Initial Access',
    shortName: 'INIT ACCESS',
    techniques: [
      {
        tid: 'T1110',
        name: 'Brute Force',
        subTechniques: [
          { tid: 'T1110.001', name: 'Password Guessing' },
          { tid: 'T1110.002', name: 'Password Cracking' },
          { tid: 'T1110.003', name: 'Password Spraying' },
          { tid: 'T1110.004', name: 'Credential Stuffing' }
        ]
      },
      {
        tid: 'T1190',
        name: 'Exploit Public-Facing Application'
      },
      {
        tid: 'T1566',
        name: 'Phishing',
        subTechniques: [
          { tid: 'T1566.001', name: 'Spearphishing Attachment' },
          { tid: 'T1566.002', name: 'Spearphishing Link' },
          { tid: 'T1566.003', name: 'Spearphishing via Service' }
        ]
      },
      {
        tid: 'T1133',
        name: 'External Remote Services'
      },
      {
        tid: 'T1200',
        name: 'Hardware Additions'
      },
      {
        tid: 'T1195',
        name: 'Supply Chain Compromise',
        subTechniques: [
          { tid: 'T1195.001', name: 'Compromise Software Dependencies and Development Tools' },
          { tid: 'T1195.002', name: 'Compromise Software Supply Chain' },
          { tid: 'T1195.003', name: 'Compromise Hardware Supply Chain' }
        ]
      },
      {
        tid: 'T1192',
        name: 'Spearphishing Link (Direct Entry)'
      },
      {
        tid: 'T1193',
        name: 'Spearphishing Attachment (Direct Entry)'
      },
      {
        tid: 'T1199',
        name: 'Trusted Relationship'
      },
      {
        tid: 'T1134',
        name: 'Exploit Internal Systems',
        subTechniques: [
          { tid: 'T1134.001', name: 'Token Impersonation/Theft' },
          { tid: 'T1134.002', name: 'Create Process with Token' },
          { tid: 'T1134.003', name: 'Make and Impersonate Token' },
          { tid: 'T1134.004', name: 'Parent PID Spoofing' },
          { tid: 'T1134.005', name: 'SID-History Injection' }
        ]
      },
      {
        tid: 'T1078',
        name: 'Valid Accounts',
        subTechniques: [
          { tid: 'T1078.001', name: 'Default Accounts' },
          { tid: 'T1078.002', name: 'Domain Accounts' },
          { tid: 'T1078.003', name: 'Local Accounts' },
          { tid: 'T1078.004', name: 'Cloud Accounts' }
        ]
      }
    ]
  },
  {
    tacticId: 'TA0002',
    name: 'Execution',
    shortName: 'EXECUTION',
    techniques: [
      {
        tid: 'T1059',
        name: 'Command and Scripting Interpreter',
        subTechniques: [
          { tid: 'T1059.001', name: 'PowerShell' },
          { tid: 'T1059.002', name: 'AppleScript' },
          { tid: 'T1059.003', name: 'Windows Command Shell' },
          { tid: 'T1059.004', name: 'Unix Shell' },
          { tid: 'T1059.005', name: 'Visual Basic' },
          { tid: 'T1059.006', name: 'Python' },
          { tid: 'T1059.007', name: 'JavaScript' },
          { tid: 'T1059.008', name: 'Network Device CLI' },
          { tid: 'T1059.009', name: 'Cloud Administration Command-Line Interface' }
        ]
      },
      {
        tid: 'T1047',
        name: 'Windows Management Instrumentation'
      },
      {
        tid: 'T1204',
        name: 'User Execution',
        subTechniques: [
          { tid: 'T1204.001', name: 'Malicious Link' },
          { tid: 'T1204.002', name: 'Malicious File' },
          { tid: 'T1204.003', name: 'Malicious Image' }
        ]
      },
      {
        tid: 'T1569',
        name: 'System Services',
        subTechniques: [
          { tid: 'T1569.001', name: 'Launch Daemon' },
          { tid: 'T1569.002', name: 'Service Execution' }
        ]
      },
      {
        tid: 'T1072',
        name: 'Software Deployment Tools'
      },
      {
        tid: 'T1106',
        name: 'Native API'
      },
      {
        tid: 'T1053',
        name: 'Scheduled Task/Job',
        subTechniques: [
          { tid: 'T1053.002', name: 'At' },
          { tid: 'T1053.003', name: 'Cron' },
          { tid: 'T1053.005', name: 'Scheduled Task' },
          { tid: 'T1053.006', name: 'Systemd Timers' },
          { tid: 'T1053.007', name: 'Container Orchestration Job' }
        ]
      },
      {
        tid: 'T1559',
        name: 'Inter-Process Communication',
        subTechniques: [
          { tid: 'T1559.001', name: 'Component Object Model' },
          { tid: 'T1559.002', name: 'Dynamic Data Exchange' },
          { tid: 'T1559.003', name: 'Hypervisor APIs' }
        ]
      },
      {
        tid: 'T1620',
        name: 'Reflective Code Loading'
      },
      {
        tid: 'T1027',
        name: 'Obfuscated Files or Information',
        subTechniques: [
          { tid: 'T1027.001', name: 'Binary Padding' },
          { tid: 'T1027.002', name: 'Software Packing' },
          { tid: 'T1027.003', name: 'Steganography' },
          { tid: 'T1027.004', name: 'Compile After Delivery' },
          { tid: 'T1027.005', name: 'Indicator Removal from Tools' },
          { tid: 'T1027.006', name: 'HTML Smuggling' },
          { tid: 'T1027.007', name: 'Dynamic API Resolution' },
          { tid: 'T1027.008', name: 'Stripped Payloads' },
          { tid: 'T1027.009', name: 'Embedded Payloads' },
          { tid: 'T1027.010', name: 'Command Obfuscation' },
          { tid: 'T1027.011', name: 'Fileless Storage' }
        ]
      },
      {
        tid: 'T1129',
        name: 'Shared Modules'
      },
      {
        tid: 'T1203',
        name: 'Exploitation for Client Execution'
      },
      {
        tid: 'T1086',
        name: 'PowerShell Remote Execution'
      },
      {
        tid: 'T1611',
        name: 'Escape to Host (Container Escape)'
      },
      {
        tid: 'T1120',
        name: 'Peripheral Device Execution'
      },
      {
        tid: 'T1035',
        name: 'WMI Execute'
      },
      {
        tid: 'T1122',
        name: 'Host process run'
      },
      {
        tid: 'T1130',
        name: 'Install Root Cert execute'
      },
      {
        tid: 'T1173',
        name: 'Script interpreter execute'
      },
      {
        tid: 'T1182',
        name: 'AppCert DLL execution'
      }
    ]
  },
  {
    tacticId: 'TA0003',
    name: 'Persistence',
    shortName: 'PERSISTENCE',
    techniques: [
      {
        tid: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        subTechniques: [
          { tid: 'T1547.001', name: 'Registry Run Keys / Startup Folder' },
          { tid: 'T1547.002', name: 'Overwriting System Binaries' },
          { tid: 'T1547.003', name: 'Execution Provider' },
          { tid: 'T1547.004', name: 'Winlogon Helper DLL' },
          { tid: 'T1547.005', name: 'Security Support Provider' },
          { tid: 'T1547.006', name: 'Kernel Modules and Extensions' },
          { tid: 'T1547.007', name: 'Re-opened Applications' },
          { tid: 'T1547.008', name: 'LSASS Driver' },
          { tid: 'T1547.009', name: 'Shortcut Modification' },
          { tid: 'T1547.010', name: 'Port Monitors' },
          { tid: 'T1547.011', name: 'Plist Modification' },
          { tid: 'T1547.012', name: 'Print Processors' },
          { tid: 'T1547.013', name: 'XDG Autostart Entries' },
          { tid: 'T1547.014', name: 'Active Setup' },
          { tid: 'T1547.015', name: 'Login Items' }
        ]
      },
      {
        tid: 'T1546',
        name: 'Event Triggered Execution',
        subTechniques: [
          { tid: 'T1546.001', name: 'Change Default File Association' },
          { tid: 'T1546.002', name: 'Screensaver' },
          { tid: 'T1546.003', name: 'Windows Management Instrumentation Event Subscription' },
          { tid: 'T1546.004', name: 'Unix Shell Configuration Modification' },
          { tid: 'T1546.005', name: 'Trap' },
          { tid: 'T1546.006', name: 'LC_LOAD_DYLIB Addition' },
          { tid: 'T1546.007', name: 'Netsh Helper DLL' },
          { tid: 'T1546.008', name: 'Accessibility Features' },
          { tid: 'T1546.009', name: 'AppCert DLLs' },
          { tid: 'T1546.010', name: 'AppInit DLLs' },
          { tid: 'T1546.011', name: 'Application Shimming' },
          { tid: 'T1546.012', name: 'Image File Execution Options Injection' },
          { tid: 'T1546.013', name: 'PowerShell Profile' },
          { tid: 'T1546.014', name: 'Emond' },
          { tid: 'T1546.015', name: 'Component Object Model Hijacking' },
          { tid: 'T1546.016', name: 'Installer Packages' }
        ]
      },
      {
        tid: 'T1098',
        name: 'Account Manipulation',
        subTechniques: [
          { tid: 'T1098.001', name: 'Additional Cloud Credentials' },
          { tid: 'T1098.002', name: 'Additional Email Delegate Permissions' },
          { tid: 'T1098.003', name: 'Add Office 365 Global Admin Role' },
          { tid: 'T1098.004', name: 'SSH Authorized Keys' },
          { tid: 'T1098.005', name: 'Device Registration' },
          { tid: 'T1098.006', name: 'Enterprise Application Credentials' }
        ]
      },
      {
        tid: 'T1505',
        name: 'Server Software Component',
        subTechniques: [
          { tid: 'T1505.001', name: 'SQL Stored Procedures' },
          { tid: 'T1505.002', name: 'Transport Agent' },
          { tid: 'T1505.003', name: 'Web Shell' },
          { tid: 'T1505.004', name: 'IIS Components' },
          { tid: 'T1505.005', name: 'Terminal Services DLL' }
        ]
      },
      {
        tid: 'T1136',
        name: 'Create Account',
        subTechniques: [
          { tid: 'T1136.001', name: 'Local Account' },
          { tid: 'T1136.002', name: 'Domain Account' },
          { tid: 'T1136.003', name: 'Cloud Account' }
        ]
      },
      {
        tid: 'T1037',
        name: 'Boot or Logon Initialization Scripts',
        subTechniques: [
          { tid: 'T1037.001', name: 'Logon Scripts (Windows)' },
          { tid: 'T1037.002', name: 'Logon Scripts (Mac)' },
          { tid: 'T1037.003', name: 'Startup Items' },
          { tid: 'T1037.004', name: 'RC Scripts' },
          { tid: 'T1037.005', name: 'Startup Scripts' }
        ]
      },
      {
        tid: 'T1543',
        name: 'Create or Modify System Process',
        subTechniques: [
          { tid: 'T1543.001', name: 'Launch Agent' },
          { tid: 'T1543.002', name: 'Systemd Service' },
          { tid: 'T1543.003', name: 'Windows Service' },
          { tid: 'T1543.004', name: 'Launch Daemon' }
        ]
      },
      {
        tid: 'T1574',
        name: 'Hijack Execution Flow',
        subTechniques: [
          { tid: 'T1574.001', name: 'DLL Search Order Hijacking' },
          { tid: 'T1574.002', name: 'DLL Side-Loading' },
          { tid: 'T1574.004', name: 'Dylib Hijacking' },
          { tid: 'T1574.005', name: 'Executable Installer File Hijacking' },
          { tid: 'T1574.006', name: 'Dynamic Linker Hijacking' },
          { tid: 'T1574.007', name: 'Path Interception by PATH Environment Variable' },
          { tid: 'T1574.008', name: 'Path Interception by Search Order Hijacking' },
          { tid: 'T1574.009', name: 'Path Interception by Unquoted Path' },
          { tid: 'T1574.010', name: 'Services File Permissions Weakness' },
          { tid: 'T1574.011', name: 'Services Registry Permissions Weakness' },
          { tid: 'T1574.012', name: 'COR_PROFILER' },
          { tid: 'T1574.013', name: 'Kernel Callback Table' },
          { tid: 'T1574.014', name: 'AppCert DLLs' },
          { tid: 'T1574.015', name: 'AppInit DLLs' }
        ]
      },
      {
        tid: 'T1108',
        name: 'Redundant Channels'
      },
      {
        tid: 'T1078',
        name: 'Valid Accounts',
        subTechniques: [
          { tid: 'T1078.001', name: 'Default Accounts' },
          { tid: 'T1078.002', name: 'Domain Accounts' },
          { tid: 'T1078.003', name: 'Local Accounts' },
          { tid: 'T1078.004', name: 'Cloud Accounts' }
        ]
      },
      {
        tid: 'T1197',
        name: 'BITS Jobs'
      },
      {
        tid: 'T1556',
        name: 'Modify Authentication Process',
        subTechniques: [
          { tid: 'T1556.001', name: 'Domain Controller Authentication Library' },
          { tid: 'T1556.002', name: 'Password Filter DLL' },
          { tid: 'T1556.003', name: 'Pluggable Authentication Modules' },
          { tid: 'T1556.004', name: 'Network Provider DLL' },
          { tid: 'T1556.005', name: 'Reversible One-Way Hashes' },
          { tid: 'T1556.006', name: 'Multi-Factor Authentication' },
          { tid: 'T1556.007', name: 'Hybrid Identity' }
        ]
      },
      {
        tid: 'T1137',
        name: 'Office Application Startup',
        subTechniques: [
          { tid: 'T1137.001', name: 'Office Template Macros' },
          { tid: 'T1137.002', name: 'Office Test' },
          { tid: 'T1137.003', name: 'Outlook Forms' },
          { tid: 'T1137.004', name: 'Outlook Home Page' },
          { tid: 'T1137.005', name: 'Outlook Rules' },
          { tid: 'T1137.006', name: 'Add-ins' }
        ]
      },
      {
        tid: 'T1176',
        name: 'Browser Extensions'
      },
      {
        tid: 'T1542',
        name: 'Pre-OS Boot',
        subTechniques: [
          { tid: 'T1542.001', name: 'System Firmware' },
          { tid: 'T1542.002', name: 'Component Firmware' },
          { tid: 'T1542.003', name: 'Bootkit' },
          { tid: 'T1542.004', name: 'ROMMON Commands' },
          { tid: 'T1542.005', name: 'TFTP Boot' }
        ]
      },
      {
        tid: 'T1525',
        name: 'Implant Internal Image'
      },
      {
        tid: 'T1198',
        name: 'Security Support Provider'
      },
      {
        tid: 'T1501',
        name: 'Systemd Services'
      },
      {
        tid: 'T1156',
        name: 'rc.common boot scripts'
      },
      {
        tid: 'T1053',
        name: 'Scheduled Task/Job',
        subTechniques: [
          { tid: 'T1053.002', name: 'At' },
          { tid: 'T1053.003', name: 'Cron' },
          { tid: 'T1053.005', name: 'Scheduled Task' },
          { tid: 'T1053.006', name: 'Systemd Timers' },
          { tid: 'T1053.007', name: 'Container Orchestration Job' }
        ]
      },
      {
        tid: 'T1608',
        name: 'Stage Capabilities',
        subTechniques: [
          { tid: 'T1608.001', name: 'Upload Malware' },
          { tid: 'T1608.002', name: 'Upload Tool' },
          { tid: 'T1608.003', name: 'Install Certificates' },
          { tid: 'T1608.004', name: 'Drive-by Target' },
          { tid: 'T1608.005', name: 'Link Target' },
          { tid: 'T1608.006', name: 'SEO Poisoning' }
        ]
      },
      {
        tid: 'T1105',
        name: 'Ingress storage persistence'
      }
    ]
  },
  {
    tacticId: 'TA0004',
    name: 'Privilege Escalation',
    shortName: 'PRIV ESC',
    techniques: [
      {
        tid: 'T1078',
        name: 'Valid Accounts',
        subTechniques: [
          { tid: 'T1078.001', name: 'Default Accounts' },
          { tid: 'T1078.002', name: 'Domain Accounts' },
          { tid: 'T1078.003', name: 'Local Accounts' },
          { tid: 'T1078.004', name: 'Cloud Accounts' }
        ]
      },
      {
        tid: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        subTechniques: [
          { tid: 'T1548.001', name: 'Setuid and Setgid' },
          { tid: 'T1548.002', name: 'Bypass User Account Control' },
          { tid: 'T1548.003', name: 'Sudo and Sudo Caching' },
          { tid: 'T1548.004', name: 'Elevate Execution Mechanism' },
          { tid: 'T1548.005', name: 'Temporary Elevated Cloud Access' }
        ]
      },
      {
        tid: 'T1068',
        name: 'Exploitation for Privilege Escalation'
      },
      {
        tid: 'T1055',
        name: 'Process Injection',
        subTechniques: [
          { tid: 'T1055.001', name: 'Dynamic-link Library Injection' },
          { tid: 'T1055.002', name: 'Portable Executable Injection' },
          { tid: 'T1055.003', name: 'Thread Execution Hijacking' },
          { tid: 'T1055.004', name: 'Asynchronous Procedure Call' },
          { tid: 'T1055.005', name: 'Thread Local Storage' },
          { tid: 'T1055.008', name: 'Ptrace System Calls' },
          { tid: 'T1055.009', name: 'Proc Memory' },
          { tid: 'T1055.011', name: 'Extra Window Memory Injection' },
          { tid: 'T1055.012', name: 'Process Hollowing' },
          { tid: 'T1055.013', name: 'Process Doppelgänger' },
          { tid: 'T1055.014', name: 'Desktop Window Manager Session Hijacking' },
          { tid: 'T1055.015', name: 'ListPlanting' }
        ]
      },
      {
        tid: 'T1574',
        name: 'Hijack Execution Flow',
        subTechniques: [
          { tid: 'T1574.001', name: 'DLL Search Order Hijacking' },
          { tid: 'T1574.002', name: 'DLL Side-Loading' },
          { tid: 'T1574.004', name: 'Dylib Hijacking' },
          { tid: 'T1574.005', name: 'Executable Installer File Hijacking' },
          { tid: 'T1574.006', name: 'Dynamic Linker Hijacking' },
          { tid: 'T1574.007', name: 'Path Interception by PATH Environment Variable' },
          { tid: 'T1574.008', name: 'Path Interception by Search Order Hijacking' },
          { tid: 'T1574.009', name: 'Path Interception by Unquoted Path' },
          { tid: 'T1574.010', name: 'Services File Permissions Weakness' },
          { tid: 'T1574.011', name: 'Services Registry Permissions Weakness' },
          { tid: 'T1574.012', name: 'COR_PROFILER' },
          { tid: 'T1574.013', name: 'Kernel Callback Table' },
          { tid: 'T1574.014', name: 'AppCert DLLs' },
          { tid: 'T1574.015', name: 'AppInit DLLs' }
        ]
      },
      {
        tid: 'T1482',
        name: 'Domain Trust Discovery'
      },
      {
        tid: 'T1037',
        name: 'Boot or Logon Initialization Scripts',
        subTechniques: [
          { tid: 'T1037.001', name: 'Logon Scripts (Windows)' },
          { tid: 'T1037.002', name: 'Logon Scripts (Mac)' },
          { tid: 'T1037.003', name: 'Startup Items' },
          { tid: 'T1037.004', name: 'RC Scripts' },
          { tid: 'T1037.005', name: 'Startup Scripts' }
        ]
      },
      {
        tid: 'T1543',
        name: 'Create or Modify System Process',
        subTechniques: [
          { tid: 'T1543.001', name: 'Launch Agent' },
          { tid: 'T1543.002', name: 'Systemd Service' },
          { tid: 'T1543.003', name: 'Windows Service' },
          { tid: 'T1543.004', name: 'Launch Daemon' }
        ]
      },
      {
        tid: 'T1484',
        name: 'Group Policy Modification',
        subTechniques: [
          { tid: 'T1484.001', name: 'Domain Policy Modification' },
          { tid: 'T1484.002', name: 'Group Policy Modification' }
        ]
      },
      {
        tid: 'T1546',
        name: 'Event Triggered Execution',
        subTechniques: [
          { tid: 'T1546.001', name: 'Change Default File Association' },
          { tid: 'T1546.002', name: 'Screensaver' },
          { tid: 'T1546.003', name: 'Windows Management Instrumentation Event Subscription' },
          { tid: 'T1546.004', name: 'Unix Shell Configuration Modification' },
          { tid: 'T1546.005', name: 'Trap' },
          { tid: 'T1546.006', name: 'LC_LOAD_DYLIB Addition' },
          { tid: 'T1546.007', name: 'Netsh Helper DLL' },
          { tid: 'T1546.008', name: 'Accessibility Features' },
          { tid: 'T1546.009', name: 'AppCert DLLs' },
          { tid: 'T1546.010', name: 'AppInit DLLs' },
          { tid: 'T1546.011', name: 'Application Shimming' },
          { tid: 'T1546.012', name: 'Image File Execution Options Injection' },
          { tid: 'T1546.013', name: 'PowerShell Profile' },
          { tid: 'T1546.014', name: 'Emond' },
          { tid: 'T1546.015', name: 'Component Object Model Hijacking' },
          { tid: 'T1546.016', name: 'Installer Packages' }
        ]
      },
      {
        tid: 'T1556',
        name: 'Modify Authentication Process',
        subTechniques: [
          { tid: 'T1556.001', name: 'Domain Controller Authentication Library' },
          { tid: 'T1556.002', name: 'Password Filter DLL' },
          { tid: 'T1556.003', name: 'Pluggable Authentication Modules' },
          { tid: 'T1556.004', name: 'Network Provider DLL' },
          { tid: 'T1556.005', name: 'Reversible One-Way Hashes' },
          { tid: 'T1556.006', name: 'Multi-Factor Authentication' },
          { tid: 'T1556.007', name: 'Hybrid Identity' }
        ]
      },
      {
        tid: 'T1134',
        name: 'Exploit Internal Systems',
        subTechniques: [
          { tid: 'T1134.001', name: 'Token Impersonation/Theft' },
          { tid: 'T1134.002', name: 'Create Process with Token' },
          { tid: 'T1134.003', name: 'Make and Impersonate Token' },
          { tid: 'T1134.004', name: 'Parent PID Spoofing' },
          { tid: 'T1134.005', name: 'SID-History Injection' }
        ]
      },
      {
        tid: 'T1203',
        name: 'Exploitation for Client Execution'
      }
    ]
  },
  {
    tacticId: 'TA0108',
    name: 'Stealth',
    shortName: 'STEALTH',
    techniques: [
      {
        tid: 'T1562',
        name: 'Impair Defenses',
        subTechniques: [
          { tid: 'T1562.001', name: 'Disable or Modify Tools' },
          { tid: 'T1562.002', name: 'Disable Windows Event Logging' },
          { tid: 'T1562.003', name: 'Impair Command History Logging' },
          { tid: 'T1562.004', name: 'Disable or Modify System Firewall' },
          { tid: 'T1562.006', name: 'Indicator Blocking' },
          { tid: 'T1562.007', name: 'Disable Boot Recovery' },
          { tid: 'T1562.008', name: 'Disable Cloud Logs' },
          { tid: 'T1562.009', name: 'Safe Mode Boot' },
          { tid: 'T1562.010', name: 'Downgrade Adversary Prevention Features' },
          { tid: 'T1562.011', name: 'Spoof Security Alerting' },
          { tid: 'T1562.012', name: 'Disable Cloud Security Services' }
        ]
      },
      {
        tid: 'T1070',
        name: 'Indicator Removal',
        subTechniques: [
          { tid: 'T1070.001', name: 'Clear Windows Event Logs' },
          { tid: 'T1070.002', name: 'Clear Linux or Mac System Logs' },
          { tid: 'T1070.003', name: 'Clear Command History' },
          { tid: 'T1070.004', name: 'File Deletion' },
          { tid: 'T1070.005', name: 'Network Share Connection Removal' },
          { tid: 'T1070.006', name: 'Timestomp' },
          { tid: 'T1070.007', name: 'Clear Mailbox Data' },
          { tid: 'T1070.008', name: 'Clear Email Collection' },
          { tid: 'T1070.009', name: 'Clear Persistence' }
        ]
      },
      {
        tid: 'T1140',
        name: 'Deobfuscate/Decode Files or Information'
      },
      {
        tid: 'T1027',
        name: 'Obfuscated Files or Information',
        subTechniques: [
          { tid: 'T1027.001', name: 'Binary Padding' },
          { tid: 'T1027.002', name: 'Software Packing' },
          { tid: 'T1027.003', name: 'Steganography' },
          { tid: 'T1027.004', name: 'Compile After Delivery' },
          { tid: 'T1027.005', name: 'Indicator Removal from Tools' },
          { tid: 'T1027.006', name: 'HTML Smuggling' },
          { tid: 'T1027.007', name: 'Dynamic API Resolution' },
          { tid: 'T1027.008', name: 'Stripped Payloads' },
          { tid: 'T1027.009', name: 'Embedded Payloads' },
          { tid: 'T1027.010', name: 'Command Obfuscation' },
          { tid: 'T1027.011', name: 'Fileless Storage' }
        ]
      },
      {
        tid: 'T1218',
        name: 'System Binary Proxy Execution',
        subTechniques: [
          { tid: 'T1218.001', name: 'Compiled HTML File' },
          { tid: 'T1218.002', name: 'Control Panel' },
          { tid: 'T1218.003', name: 'CMSTP' },
          { tid: 'T1218.004', name: 'InstallUtil' },
          { tid: 'T1218.005', name: 'Mshtml' },
          { tid: 'T1218.007', name: 'Msiexec' },
          { tid: 'T1218.008', name: 'Odbcconf' },
          { tid: 'T1218.009', name: 'Regsvcs/Regasm' },
          { tid: 'T1218.010', name: 'Regsvr32' },
          { tid: 'T1218.011', name: 'Rundll32' },
          { tid: 'T1218.012', name: 'Verclsid' },
          { tid: 'T1218.013', name: 'Mavinject' },
          { tid: 'T1218.014', name: 'MMC' },
          { tid: 'T1218.015', name: 'Server Manager' }
        ]
      },
      {
        tid: 'T1207',
        name: 'Rogue Domain Controller'
      },
      {
        tid: 'T1497',
        name: 'Virtualization/Sandbox Evasion',
        subTechniques: [
          { tid: 'T1497.001', name: 'System Checks' },
          { tid: 'T1497.002', name: 'User Activity Discovery' },
          { tid: 'T1497.003', name: 'Time Based Evasion' }
        ]
      },
      {
        tid: 'T1564',
        name: 'Hide Artifacts',
        subTechniques: [
          { tid: 'T1564.001', name: 'Hidden Files and Directories' },
          { tid: 'T1564.002', name: 'Hidden Users' },
          { tid: 'T1564.003', name: 'Hidden Window' },
          { tid: 'T1564.004', name: 'NTFS File Attributes' },
          { tid: 'T1564.005', name: 'Hidden File System' },
          { tid: 'T1564.006', name: 'Run Virtual Instance' },
          { tid: 'T1564.007', name: 'VPC Endpoint Service' },
          { tid: 'T1564.008', name: 'Email Hiding Rules' },
          { tid: 'T1564.009', name: 'Resource Forking' },
          { tid: 'T1564.010', name: 'Process Argument Spoofing' },
          { tid: 'T1564.011', name: 'Hidden Active Directory Objects' }
        ]
      },
      {
        tid: 'T1620',
        name: 'Reflective Code Loading'
      },
      {
        tid: 'T1036',
        name: 'Masquerading',
        subTechniques: [
          { tid: 'T1036.001', name: 'Invalid Code Signature' },
          { tid: 'T1036.002', name: 'Right-to-Left Override' },
          { tid: 'T1036.003', name: 'Rename System Utilities' },
          { tid: 'T1036.004', name: 'Masquerade Task or Service' },
          { tid: 'T1036.005', name: 'Match Legitimate Name or Location' },
          { tid: 'T1036.006', name: 'Space after Extension' },
          { tid: 'T1036.007', name: 'Double Extension' },
          { tid: 'T1036.008', name: 'Masquerade File Type' },
          { tid: 'T1036.009', name: 'Break OS Desktop Locking' }
        ]
      },
      {
        tid: 'T1222',
        name: 'File and Directory Permissions Modification',
        subTechniques: [
          { tid: 'T1222.001', name: 'Windows File and Directory Permissions Modification' },
          { tid: 'T1222.002', name: 'Linux and Mac File and Directory Permissions Modification' }
        ]
      },
      {
        tid: 'T1553',
        name: 'Subvert Trust Controls',
        subTechniques: [
          { tid: 'T1553.001', name: 'Gatekeeper Bypass' },
          { tid: 'T1553.002', name: 'Code Signing' },
          { tid: 'T1553.003', name: 'SIP and Rootless Bypass' },
          { tid: 'T1553.004', name: 'Install Root Certificate' },
          { tid: 'T1553.005', name: 'Mark-of-the-Web Bypass' },
          { tid: 'T1553.006', name: 'Code Signing Policy Modification' }
        ]
      },
      {
        tid: 'T1001',
        name: 'Data Obfuscation',
        subTechniques: [
          { tid: 'T1001.001', name: 'Junk Data' },
          { tid: 'T1001.002', name: 'Steganography' },
          { tid: 'T1001.003', name: 'Protocol Impersonation' }
        ]
      },
      {
        tid: 'T1006',
        name: 'Direct Volume Access'
      },
      {
        tid: 'T1112',
        name: 'Modify Registry'
      },
      {
        tid: 'T1197',
        name: 'BITS Jobs'
      },
      {
        tid: 'T1205',
        name: 'Traffic Signaling',
        subTechniques: [
          { tid: 'T1205.001', name: 'Port Knocking' },
          { tid: 'T1205.002', name: 'Socket Filters' }
        ]
      },
      {
        tid: 'T1216',
        name: 'Script Proxy Execution',
        subTechniques: [
          { tid: 'T1216.001', name: 'PubPrn' },
          { tid: 'T1216.002', name: 'SyncAppPublishingServer' }
        ]
      },
      {
        tid: 'T1220',
        name: 'XSL Script Processing'
      },
      {
        tid: 'T1550',
        name: 'Use Alternate Authentication Material',
        subTechniques: [
          { tid: 'T1550.001', name: 'Application Access Token' },
          { tid: 'T1550.002', name: 'Pass the Hash' },
          { tid: 'T1550.003', name: 'Pass the Ticket' },
          { tid: 'T1550.004', name: 'Web Session Cookie' }
        ]
      },
      {
        tid: 'T1574',
        name: 'Hijack Execution Flow',
        subTechniques: [
          { tid: 'T1574.001', name: 'DLL Search Order Hijacking' },
          { tid: 'T1574.002', name: 'DLL Side-Loading' },
          { tid: 'T1574.004', name: 'Dylib Hijacking' },
          { tid: 'T1574.005', name: 'Executable Installer File Hijacking' },
          { tid: 'T1574.006', name: 'Dynamic Linker Hijacking' },
          { tid: 'T1574.007', name: 'Path Interception by PATH Environment Variable' },
          { tid: 'T1574.008', name: 'Path Interception by Search Order Hijacking' },
          { tid: 'T1574.009', name: 'Path Interception by Unquoted Path' },
          { tid: 'T1574.010', name: 'Services File Permissions Weakness' },
          { tid: 'T1574.011', name: 'Services Registry Permissions Weakness' },
          { tid: 'T1574.012', name: 'COR_PROFILER' },
          { tid: 'T1574.013', name: 'Kernel Callback Table' },
          { tid: 'T1574.014', name: 'AppCert DLLs' },
          { tid: 'T1574.015', name: 'AppInit DLLs' }
        ]
      },
      {
        tid: 'T1601',
        name: 'Modify System Image',
        subTechniques: [
          { tid: 'T1601.001', name: 'Patch System Image' },
          { tid: 'T1601.002', name: 'Downgrade System Image' }
        ]
      },
      {
        tid: 'T1556',
        name: 'Modify Authentication Process',
        subTechniques: [
          { tid: 'T1556.001', name: 'Domain Controller Authentication Library' },
          { tid: 'T1556.002', name: 'Password Filter DLL' },
          { tid: 'T1556.003', name: 'Pluggable Authentication Modules' },
          { tid: 'T1556.004', name: 'Network Provider DLL' },
          { tid: 'T1556.005', name: 'Reversible One-Way Hashes' },
          { tid: 'T1556.006', name: 'Multi-Factor Authentication' },
          { tid: 'T1556.007', name: 'Hybrid Identity' }
        ]
      },
      {
        tid: 'T1622',
        name: 'Debugger Evasion'
      },
      {
        tid: 'T1613',
        name: 'Container and Resource Discovery'
      },
      {
        tid: 'T1614',
        name: 'System Location Discovery',
        subTechniques: [
          { tid: 'T1614.001', name: 'System Language Discovery' },
          { tid: 'T1614.002', name: 'IP Addresses' }
        ]
      },
      {
        tid: 'T1132',
        name: 'Data Encoding',
        subTechniques: [
          { tid: 'T1132.001', name: 'Standard Encoding' },
          { tid: 'T1132.002', name: 'Non-Standard Encoding' }
        ]
      },
      {
        tid: 'T1502',
        name: 'Local VM Evasion'
      },
      {
        tid: 'T1513',
        name: 'Covert Channels'
      },
      {
        tid: 'T1520',
        name: 'Covert Tunnels'
      }
    ]
  },
  {
    tacticId: 'TA0005',
    name: 'Defence Impairment',
    shortName: 'DEF IMPAIR',
    techniques: [
      {
        tid: 'T1562',
        name: 'Impair Defenses',
        subTechniques: [
          { tid: 'T1562.001', name: 'Disable or Modify Tools' },
          { tid: 'T1562.002', name: 'Disable Windows Event Logging' },
          { tid: 'T1562.003', name: 'Impair Command History Logging' },
          { tid: 'T1562.004', name: 'Disable or Modify System Firewall' },
          { tid: 'T1562.006', name: 'Indicator Blocking' },
          { tid: 'T1562.007', name: 'Disable Boot Recovery' },
          { tid: 'T1562.008', name: 'Disable Cloud Logs' },
          { tid: 'T1562.009', name: 'Safe Mode Boot' },
          { tid: 'T1562.010', name: 'Downgrade Adversary Prevention Features' },
          { tid: 'T1562.011', name: 'Spoof Security Alerting' },
          { tid: 'T1562.012', name: 'Disable Cloud Security Services' }
        ]
      },
      {
        tid: 'T1070',
        name: 'Indicator Removal',
        subTechniques: [
          { tid: 'T1070.001', name: 'Clear Windows Event Logs' },
          { tid: 'T1070.002', name: 'Clear Linux or Mac System Logs' },
          { tid: 'T1070.003', name: 'Clear Command History' },
          { tid: 'T1070.004', name: 'File Deletion' },
          { tid: 'T1070.005', name: 'Network Share Connection Removal' },
          { tid: 'T1070.006', name: 'Timestomp' },
          { tid: 'T1070.007', name: 'Clear Mailbox Data' },
          { tid: 'T1070.008', name: 'Clear Email Collection' },
          { tid: 'T1070.009', name: 'Clear Persistence' }
        ]
      },
      {
        tid: 'T1222',
        name: 'File and Directory Permissions Modification',
        subTechniques: [
          { tid: 'T1222.001', name: 'Windows File and Directory Permissions Modification' },
          { tid: 'T1222.002', name: 'Linux and Mac File and Directory Permissions Modification' }
        ]
      },
      {
        tid: 'T1553',
        name: 'Subvert Trust Controls',
        subTechniques: [
          { tid: 'T1553.001', name: 'Gatekeeper Bypass' },
          { tid: 'T1553.002', name: 'Code Signing' },
          { tid: 'T1553.003', name: 'SIP and Rootless Bypass' },
          { tid: 'T1553.004', name: 'Install Root Certificate' },
          { tid: 'T1553.005', name: 'Mark-of-the-Web Bypass' },
          { tid: 'T1553.006', name: 'Code Signing Policy Modification' }
        ]
      },
      {
        tid: 'T1140',
        name: 'Deobfuscate/Decode Files or Information'
      },
      {
        tid: 'T1218',
        name: 'System Binary Proxy Execution',
        subTechniques: [
          { tid: 'T1218.001', name: 'Compiled HTML File' },
          { tid: 'T1218.002', name: 'Control Panel' },
          { tid: 'T1218.003', name: 'CMSTP' },
          { tid: 'T1218.004', name: 'InstallUtil' },
          { tid: 'T1218.005', name: 'Mshtml' },
          { tid: 'T1218.007', name: 'Msiexec' },
          { tid: 'T1218.008', name: 'Odbcconf' },
          { tid: 'T1218.009', name: 'Regsvcs/Regasm' },
          { tid: 'T1218.010', name: 'Regsvr32' },
          { tid: 'T1218.011', name: 'Rundll32' },
          { tid: 'T1218.012', name: 'Verclsid' },
          { tid: 'T1218.013', name: 'Mavinject' },
          { tid: 'T1218.014', name: 'MMC' },
          { tid: 'T1218.015', name: 'Server Manager' }
        ]
      },
      {
        tid: 'T1202',
        name: 'Indirect Command Execution'
      },
      {
        tid: 'T1480',
        name: 'Execution Guardrails',
        subTechniques: [
          { tid: 'T1480.001', name: 'Environmental Keying' }
        ]
      },
      {
        tid: 'T1027',
        name: 'Obfuscated Files or Information',
        subTechniques: [
          { tid: 'T1027.001', name: 'Binary Padding' },
          { tid: 'T1027.002', name: 'Software Packing' },
          { tid: 'T1027.003', name: 'Steganography' },
          { tid: 'T1027.004', name: 'Compile After Delivery' },
          { tid: 'T1027.005', name: 'Indicator Removal from Tools' },
          { tid: 'T1027.006', name: 'HTML Smuggling' },
          { tid: 'T1027.007', name: 'Dynamic API Resolution' },
          { tid: 'T1027.008', name: 'Stripped Payloads' },
          { tid: 'T1027.009', name: 'Embedded Payloads' },
          { tid: 'T1027.010', name: 'Command Obfuscation' },
          { tid: 'T1027.011', name: 'Fileless Storage' }
        ]
      },
      {
        tid: 'T1036',
        name: 'Masquerading',
        subTechniques: [
          { tid: 'T1036.001', name: 'Invalid Code Signature' },
          { tid: 'T1036.002', name: 'Right-to-Left Override' },
          { tid: 'T1036.003', name: 'Rename System Utilities' },
          { tid: 'T1036.004', name: 'Masquerade Task or Service' },
          { tid: 'T1036.005', name: 'Match Legitimate Name or Location' },
          { tid: 'T1036.006', name: 'Space after Extension' },
          { tid: 'T1036.007', name: 'Double Extension' },
          { tid: 'T1036.008', name: 'Masquerade File Type' },
          { tid: 'T1036.009', name: 'Break OS Desktop Locking' }
        ]
      },
      {
        tid: 'T1134',
        name: 'Exploit Internal Systems',
        subTechniques: [
          { tid: 'T1134.001', name: 'Token Impersonation/Theft' },
          { tid: 'T1134.002', name: 'Create Process with Token' },
          { tid: 'T1134.003', name: 'Make and Impersonate Token' },
          { tid: 'T1134.004', name: 'Parent PID Spoofing' },
          { tid: 'T1134.005', name: 'SID-History Injection' }
        ]
      },
      {
        tid: 'T1564',
        name: 'Hide Artifacts',
        subTechniques: [
          { tid: 'T1564.001', name: 'Hidden Files and Directories' },
          { tid: 'T1564.002', name: 'Hidden Users' },
          { tid: 'T1564.003', name: 'Hidden Window' },
          { tid: 'T1564.004', name: 'NTFS File Attributes' },
          { tid: 'T1564.005', name: 'Hidden File System' },
          { tid: 'T1564.006', name: 'Run Virtual Instance' },
          { tid: 'T1564.007', name: 'VPC Endpoint Service' },
          { tid: 'T1564.008', name: 'Email Hiding Rules' },
          { tid: 'T1564.009', name: 'Resource Forking' },
          { tid: 'T1564.010', name: 'Process Argument Spoofing' },
          { tid: 'T1564.011', name: 'Hidden Active Directory Objects' }
        ]
      },
      {
        tid: 'T1620',
        name: 'Reflective Code Loading'
      },
      {
        tid: 'T1207',
        name: 'Rogue Domain Controller'
      },
      {
        tid: 'T1212',
        name: 'Exploitation for Defense Evasion'
      },
      {
        tid: 'T1223',
        name: 'Signed Binary Proxy Execution'
      },
      {
        tid: 'T1500',
        name: 'Use of Alternative Registry'
      },
      {
        tid: 'T1501',
        name: 'Systemd Services'
      }
    ]
  },
  {
    tacticId: 'TA0006',
    name: 'Credential Access',
    shortName: 'CRED ACCESS',
    techniques: [
      {
        tid: 'T1003',
        name: 'OS Credential Dumping',
        subTechniques: [
          { tid: 'T1003.001', name: 'LSASS Memory' },
          { tid: 'T1003.002', name: 'Security Account Manager' },
          { tid: 'T1003.003', name: 'LSA Secrets' },
          { tid: 'T1003.004', name: 'Active Directory Database' },
          { tid: 'T1003.005', name: 'Cached Domain Credentials' },
          { tid: 'T1003.006', name: 'DCSync' },
          { tid: 'T1003.007', name: 'Proc Filesystem' },
          { tid: 'T1003.008', name: '/etc/passwd and /etc/shadow' }
        ]
      },
      {
        tid: 'T1558',
        name: 'Use Alternate Authentication Material',
        subTechniques: [
          { tid: 'T1558.001', name: 'Golden Ticket' },
          { tid: 'T1558.002', name: 'Silver Ticket' },
          { tid: 'T1558.003', name: 'Kerberoasting' },
          { tid: 'T1558.004', name: 'AS-REP Roasting' }
        ]
      },
      {
        tid: 'T1110',
        name: 'Brute Force',
        subTechniques: [
          { tid: 'T1110.001', name: 'Password Guessing' },
          { tid: 'T1110.002', name: 'Password Cracking' },
          { tid: 'T1110.003', name: 'Password Spraying' },
          { tid: 'T1110.004', name: 'Credential Stuffing' }
        ]
      },
      {
        tid: 'T1555',
        name: 'Credentials from Password Stores',
        subTechniques: [
          { tid: 'T1555.001', name: 'Keychain' },
          { tid: 'T1555.002', name: 'Security-related Command-Line Tools' },
          { tid: 'T1555.003', name: 'Credentials from Web Browsers' },
          { tid: 'T1555.004', name: 'Windows Credential Manager' },
          { tid: 'T1555.005', name: 'Password Managers' },
          { tid: 'T1555.006', name: 'Cloud Command-Line Metadata' }
        ]
      },
      {
        tid: 'T1056',
        name: 'Input Capture',
        subTechniques: [
          { tid: 'T1056.001', name: 'Keylogging' },
          { tid: 'T1056.002', name: 'GUI Input Capture' },
          { tid: 'T1056.003', name: 'Web Portal Modification' },
          { tid: 'T1056.004', name: 'Credential API Hooking' }
        ]
      },
      {
        tid: 'T1212',
        name: 'Exploitation for Defense Evasion'
      },
      {
        tid: 'T1606',
        name: 'Forge Web Credentials',
        subTechniques: [
          { tid: 'T1606.001', name: 'Web Cookies' },
          { tid: 'T1606.002', name: 'SAML Tokens' }
        ]
      },
      {
        tid: 'T1557',
        name: 'Adversary-in-the-Middle',
        subTechniques: [
          { tid: 'T1557.001', name: 'LLMNR/NBT-NS Poisoning and SMB Relay' },
          { tid: 'T1557.002', name: 'ARP Cache Poisoning' },
          { tid: 'T1557.003', name: 'DHCP Spoofing' }
        ]
      },
      {
        tid: 'T1040',
        name: 'Network Sniffing'
      },
      {
        tid: 'T1111',
        name: 'Two-Factor Authentication Bypass'
      },
      {
        tid: 'T1171',
        name: 'LLMNR/NBT-NS Poisoning and SMB Relay'
      },
      {
        tid: 'T1179',
        name: 'Hooking for Credential Access'
      },
      {
        tid: 'T1187',
        name: 'Forced Authentication'
      },
      {
        tid: 'T1539',
        name: 'Steal Web Session Cookie'
      },
      {
        tid: 'T1552',
        name: 'Unsecured Credentials',
        subTechniques: [
          { tid: 'T1552.001', name: 'Credentials In Files' },
          { tid: 'T1552.002', name: 'Credentials in Registry' },
          { tid: 'T1552.003', name: 'Bash History' },
          { tid: 'T1552.004', name: 'Private Keys' },
          { tid: 'T1552.005', name: 'Cloud Instance Metadata API' },
          { tid: 'T1552.006', name: 'Group Policy Preferences' },
          { tid: 'T1552.007', name: 'Container API' }
        ]
      },
      {
        tid: 'T1603',
        name: 'Active Capture'
      },
      {
        tid: 'T1621',
        name: 'Multi-Factor Authentication Request Generation'
      }
    ]
  },
  {
    tacticId: 'TA0007',
    name: 'Discovery',
    shortName: 'DISCOVERY',
    techniques: [
      {
        tid: 'T1087',
        name: 'Account Discovery',
        subTechniques: [
          { tid: 'T1087.001', name: 'Local Accounts' },
          { tid: 'T1087.002', name: 'Domain Accounts' },
          { tid: 'T1087.003', name: 'Email Accounts' },
          { tid: 'T1087.004', name: 'Cloud Accounts' }
        ]
      },
      {
        tid: 'T1082',
        name: 'System Information Discovery',
        subTechniques: [
          { tid: 'T1082.001', name: 'OS Version info detection' },
          { tid: 'T1082.002', name: 'CPU Architecture detection' }
        ]
      },
      {
        tid: 'T1016',
        name: 'System Network Connection Discovery',
        subTechniques: [
          { tid: 'T1016.001', name: 'Internet Connection Discovery' }
        ]
      },
      {
        tid: 'T1049',
        name: 'System Network Connections Discovery'
      },
      {
        tid: 'T1057',
        name: 'Process Discovery'
      },
      {
        tid: 'T1012',
        name: 'Query Registry'
      },
      {
        tid: 'T1018',
        name: 'Remote System Discovery',
        subTechniques: [
          { tid: 'T1018.001', name: 'IP Scan Remote hosts' }
        ]
      },
      {
        tid: 'T1124',
        name: 'System Time Discovery'
      },
      {
        tid: 'T1135',
        name: 'Network Share Discovery',
        subTechniques: [
          { tid: 'T1135.001', name: 'SMB Share Scan probing' }
        ]
      },
      {
        tid: 'T1069',
        name: 'Permission Groups Discovery',
        subTechniques: [
          { tid: 'T1069.001', name: 'Local Groups' },
          { tid: 'T1069.002', name: 'Domain Groups' },
          { tid: 'T1069.003', name: 'Cloud Groups' }
        ]
      },
      {
        tid: 'T1482',
        name: 'Domain Trust Discovery'
      },
      {
        tid: 'T1083',
        name: 'File and Directory Discovery'
      },
      {
        tid: 'T1046',
        name: 'Network Service Discovery',
        subTechniques: [
          { tid: 'T1046.001', name: 'Port Scans detection parameters' }
        ]
      },
      {
        tid: 'T1120',
        name: 'Peripheral Device Execution'
      },
      {
        tid: 'T1102',
        name: 'Web Service Discovery',
        subTechniques: [
          { tid: 'T1102.001', name: 'Dead Drop Resolver' },
          { tid: 'T1102.002', name: 'Bidirectional Communication' },
          { tid: 'T1102.003', name: 'One-Way Communication' }
        ]
      },
      {
        tid: 'T1613',
        name: 'Container and Resource Discovery'
      },
      {
        tid: 'T1518',
        name: 'Software Discovery',
        subTechniques: [
          { tid: 'T1518.001', name: 'Security Software Discovery' }
        ]
      },
      {
        tid: 'T1007',
        name: 'System Service Discovery'
      },
      {
        tid: 'T1201',
        name: 'Password Policy Discovery'
      },
      {
        tid: 'T1119',
        name: 'System Network Configuration Discovery'
      },
      {
        tid: 'T1497',
        name: 'Virtualization/Sandbox Evasion',
        subTechniques: [
          { tid: 'T1497.001', name: 'System Checks' },
          { tid: 'T1497.002', name: 'User Activity Discovery' },
          { tid: 'T1497.003', name: 'Time Based Evasion' }
        ]
      },
      {
        tid: 'T1033',
        name: 'System Owner/User Discovery'
      },
      {
        tid: 'T1010',
        name: 'Application Window Discovery'
      },
      {
        tid: 'T1414',
        name: 'Audio Input Discovery'
      },
      {
        tid: 'T1526',
        name: 'Cloud Service Discovery'
      },
      {
        tid: 'T1538',
        name: 'Cloud Directory Discovery'
      },
      {
        tid: 'T1614',
        name: 'System Location Discovery',
        subTechniques: [
          { tid: 'T1614.001', name: 'System Language Discovery' },
          { tid: 'T1614.002', name: 'IP Addresses' }
        ]
      },
      {
        tid: 'T1615',
        name: 'Group Policy Discovery'
      },
      {
        tid: 'T1619',
        name: 'Cloud Storage Object Discovery'
      },
      {
        tid: 'T1045',
        name: 'Local Port Discovery'
      },
      {
        tid: 'T1043',
        name: 'Service Ports Scan'
      },
      {
        tid: 'T1040',
        name: 'Network Sniffing'
      },
      {
        tid: 'T1014',
        name: 'Boot Rom Discovery'
      },
      {
        tid: 'T1015',
        name: 'Query Active Users'
      }
    ]
  },
  {
    tacticId: 'TA0008',
    name: 'Lateral Movement',
    shortName: 'LAT MOV',
    techniques: [
      {
        tid: 'T1021',
        name: 'Remote Services',
        subTechniques: [
          { tid: 'T1021.001', name: 'Remote Desktop Protocol' },
          { tid: 'T1021.002', name: 'SMB/Windows Admin Shares' },
          { tid: 'T1021.003', name: 'Distributed Component Object Model' },
          { tid: 'T1021.004', name: 'SSH' },
          { tid: 'T1021.005', name: 'VNC' },
          { tid: 'T1021.006', name: 'Windows Remote Management' }
        ]
      },
      {
        tid: 'T1090',
        name: 'Proxy',
        subTechniques: [
          { tid: 'T1090.001', name: 'Internal Proxy' },
          { tid: 'T1090.002', name: 'External Proxy' },
          { tid: 'T1090.003', name: 'Multi-hop Proxy' },
          { tid: 'T1090.004', name: 'Domain Fronting' }
        ]
      },
      {
        tid: 'T1091',
        name: 'Replication Through Removable Media'
      },
      {
        tid: 'T1570',
        name: 'Lateral Tool Transfer'
      },
      {
        tid: 'T1563',
        name: 'Remote Service Session Hijacking',
        subTechniques: [
          { tid: 'T1563.001', name: 'SSH Session Hijacking' },
          { tid: 'T1563.002', name: 'RDP Session Hijacking' }
        ]
      },
      {
        tid: 'T1550',
        name: 'Use Alternate Authentication Material',
        subTechniques: [
          { tid: 'T1550.001', name: 'Application Access Token' },
          { tid: 'T1550.002', name: 'Pass the Hash' },
          { tid: 'T1550.003', name: 'Pass the Ticket' },
          { tid: 'T1550.004', name: 'Web Session Cookie' }
        ]
      },
      {
        tid: 'T1210',
        name: 'Exploitation of Remote Services'
      },
      {
        tid: 'T1219',
        name: 'Remote Access Software'
      },
      {
        tid: 'T1544',
        name: 'Direct Admin Shares Execution'
      }
    ]
  },
  {
    tacticId: 'TA0009',
    name: 'Collection',
    shortName: 'COLLECTION',
    techniques: [
      {
        tid: 'T1560',
        name: 'Archive Collected Data',
        subTechniques: [
          { tid: 'T1560.001', name: 'Archive via Utility' },
          { tid: 'T1560.002', name: 'Archive via Library' },
          { tid: 'T1560.003', name: 'Archive via Custom Method' }
        ]
      },
      {
        tid: 'T1005',
        name: 'Data from Local System'
      },
      {
        tid: 'T1114',
        name: 'Email Collection',
        subTechniques: [
          { tid: 'T1114.001', name: 'Local Email Collection' },
          { tid: 'T1114.002', name: 'Remote Email Collection' },
          { tid: 'T1114.003', name: 'Email Forwarding Rule' }
        ]
      },
      {
        tid: 'T1113',
        name: 'Screen Capture'
      },
      {
        tid: 'T1123',
        name: 'Audio Capture'
      },
      {
        tid: 'T1125',
        name: 'Video Capture'
      },
      {
        tid: 'T1115',
        name: 'Clipboard Data'
      },
      {
        tid: 'T1074',
        name: 'Data Staged',
        subTechniques: [
          { tid: 'T1074.001', name: 'Local Data Staging' },
          { tid: 'T1074.002', name: 'Remote Data Staging' }
        ]
      },
      {
        tid: 'T1185',
        name: 'Man-in-the-Browser'
      },
      {
        tid: 'T1056',
        name: 'Input Capture',
        subTechniques: [
          { tid: 'T1056.001', name: 'Keylogging' },
          { tid: 'T1056.002', name: 'GUI Input Capture' },
          { tid: 'T1056.003', name: 'Web Portal Modification' },
          { tid: 'T1056.004', name: 'Credential API Hooking' }
        ]
      },
      {
        tid: 'T1025',
        name: 'Data from Removable Media'
      },
      {
        tid: 'T1039',
        name: 'Data from Network Shared Drive'
      },
      {
        tid: 'T1213',
        name: 'Data from Information Repositories',
        subTechniques: [
          { tid: 'T1213.001', name: 'Confluence' },
          { tid: 'T1213.002', name: 'SharePoint' },
          { tid: 'T1213.003', name: 'Wiki' }
        ]
      },
      {
        tid: 'T1124',
        name: 'System Time Discovery'
      },
      {
        tid: 'T1539',
        name: 'Steal Web Session Cookie'
      },
      {
        tid: 'T1602',
        name: 'Wireless Sniffing Collection'
      },
      {
        tid: 'T1612',
        name: 'Local Container Details Collection'
      }
    ]
  },
  {
    tacticId: 'TA0011',
    name: 'Command and Control',
    shortName: 'C2',
    techniques: [
      {
        tid: 'T1071',
        name: 'Application Layer Protocol',
        subTechniques: [
          { tid: 'T1071.001', name: 'Web Protocols' },
          { tid: 'T1071.002', name: 'File Transfer Protocols' },
          { tid: 'T1071.003', name: 'Mail Protocols' },
          { tid: 'T1071.004', name: 'DNS' }
        ]
      },
      {
        tid: 'T1568',
        name: 'Dynamic Resolution',
        subTechniques: [
          { tid: 'T1568.001', name: 'Fast Flux DNS' },
          { tid: 'T1568.002', name: 'Domain Generation Algorithms' },
          { tid: 'T1568.003', name: 'DNS Calculation' }
        ]
      },
      {
        tid: 'T1095',
        name: 'Non-Application Layer Protocol'
      },
      {
        tid: 'T1090',
        name: 'Proxy',
        subTechniques: [
          { tid: 'T1090.001', name: 'Internal Proxy' },
          { tid: 'T1090.002', name: 'External Proxy' },
          { tid: 'T1090.003', name: 'Multi-hop Proxy' },
          { tid: 'T1090.004', name: 'Domain Fronting' }
        ]
      },
      {
        tid: 'T1105',
        name: 'Ingress storage persistence'
      },
      {
        tid: 'T1573',
        name: 'Encrypted Channel',
        subTechniques: [
          { tid: 'T1573.001', name: 'Symmetric Cryptography' },
          { tid: 'T1573.002', name: 'Asymmetric Cryptography' }
        ]
      },
      {
        tid: 'T1219',
        name: 'Remote Access Software'
      },
      {
        tid: 'T1132',
        name: 'Data Encoding',
        subTechniques: [
          { tid: 'T1132.001', name: 'Standard Encoding' },
          { tid: 'T1132.002', name: 'Non-Standard Encoding' }
        ]
      },
      {
        tid: 'T1008',
        name: 'Fallback Channels'
      },
      {
        tid: 'T1102',
        name: 'Web Service Discovery',
        subTechniques: [
          { tid: 'T1102.001', name: 'Dead Drop Resolver' },
          { tid: 'T1102.002', name: 'Bidirectional Communication' },
          { tid: 'T1102.003', name: 'One-Way Communication' }
        ]
      },
      {
        tid: 'T1104',
        name: 'Multi-Stage Channels'
      },
      {
        tid: 'T1101',
        name: 'Proxy Redirection'
      },
      {
        tid: 'T1171',
        name: 'LLMNR/NBT-NS Poisoning and SMB Relay'
      },
      {
        tid: 'T1571',
        name: 'Non-Standard Port'
      },
      {
        tid: 'T1572',
        name: 'Protocol Tunneling'
      },
      {
        tid: 'T1205',
        name: 'Traffic Signaling',
        subTechniques: [
          { tid: 'T1205.001', name: 'Port Knocking' },
          { tid: 'T1205.002', name: 'Socket Filters' }
        ]
      },
      {
        tid: 'T1001',
        name: 'Data Obfuscation',
        subTechniques: [
          { tid: 'T1001.001', name: 'Junk Data' },
          { tid: 'T1001.002', name: 'Steganography' },
          { tid: 'T1001.003', name: 'Protocol Impersonation' }
        ]
      },
      {
        tid: 'T1024',
        name: 'Custom Protocol'
      }
    ]
  },
  {
    tacticId: 'TA0010',
    name: 'Exfiltration',
    shortName: 'EXFIL',
    techniques: [
      {
        tid: 'T1048',
        name: 'Exfiltration Over Alternative Protocol',
        subTechniques: [
          { tid: 'T1048.001', name: 'Exfiltration Over Symmetric Encrypted Non-C2 Channel' },
          { tid: 'T1048.002', name: 'Exfiltration Over Asymmetric Encrypted Non-C2 Channel' },
          { tid: 'T1048.003', name: 'Exfiltration Over Unencrypted/Obfuscated Non-C2 Channel' }
        ]
      },
      {
        tid: 'T1567',
        name: 'Exfiltration Over Web Service',
        subTechniques: [
          { tid: 'T1567.001', name: 'Exfiltration to Code Repository' },
          { tid: 'T1567.002', name: 'Exfiltration to Cloud Storage' },
          { tid: 'T1567.003', name: 'Exfiltration to Text Storage Sites' }
        ]
      },
      {
        tid: 'T1052',
        name: 'Exfiltration Over Physical Medium',
        subTechniques: [
          { tid: 'T1052.001', name: 'Exfiltration Over USB' }
        ]
      },
      {
        tid: 'T1020',
        name: 'Automated Exfiltration',
        subTechniques: [
          { tid: 'T1020.001', name: 'Traffic Duplication' }
        ]
      },
      {
        tid: 'T1011',
        name: 'Exfiltration Over Bluetooth'
      },
      {
        tid: 'T1029',
        name: 'Scheduled Transfer'
      },
      {
        tid: 'T1030',
        name: 'Data Transfer Size Limits'
      },
      {
        tid: 'T1041',
        name: 'Exfiltration Over C2 Channel'
      },
      {
        tid: 'T1574',
        name: 'Hijack Execution Flow',
        subTechniques: [
          { tid: 'T1574.001', name: 'DLL Search Order Hijacking' },
          { tid: 'T1574.002', name: 'DLL Side-Loading' },
          { tid: 'T1574.004', name: 'Dylib Hijacking' },
          { tid: 'T1574.005', name: 'Executable Installer File Hijacking' },
          { tid: 'T1574.006', name: 'Dynamic Linker Hijacking' },
          { tid: 'T1574.007', name: 'Path Interception by PATH Environment Variable' },
          { tid: 'T1574.008', name: 'Path Interception by Search Order Hijacking' },
          { tid: 'T1574.009', name: 'Path Interception by Unquoted Path' },
          { tid: 'T1574.010', name: 'Services File Permissions Weakness' },
          { tid: 'T1574.011', name: 'Services Registry Permissions Weakness' },
          { tid: 'T1574.012', name: 'COR_PROFILER' },
          { tid: 'T1574.013', name: 'Kernel Callback Table' },
          { tid: 'T1574.014', name: 'AppCert DLLs' },
          { tid: 'T1574.015', name: 'AppInit DLLs' }
        ]
      }
    ]
  },
  {
    tacticId: 'TA0040',
    name: 'Impact',
    shortName: 'IMPACT',
    techniques: [
      {
        tid: 'T1486',
        name: 'Data Encrypted for Impact'
      },
      {
        tid: 'T1529',
        name: 'System Shutdown/Reboot'
      },
      {
        tid: 'T1485',
        name: 'Data Destruction'
      },
      {
        tid: 'T1491',
        name: 'Defacement',
        subTechniques: [
          { tid: 'T1491.001', name: 'Internal Defacement' },
          { tid: 'T1491.002', name: 'External Defacement' }
        ]
      },
      {
        tid: 'T1489',
        name: 'Service Stop'
      },
      {
        tid: 'T1490',
        name: 'Inhibit System Recovery'
      },
      {
        tid: 'T1498',
        name: 'Network Denial of Service',
        subTechniques: [
          { tid: 'T1498.001', name: 'Direct Network Flood' },
          { tid: 'T1498.002', name: 'Reflection Amplification' }
        ]
      },
      {
        tid: 'T1499',
        name: 'Endpoint Denial of Service',
        subTechniques: [
          { tid: 'T1499.001', name: 'OS Limit Exhaustion' },
          { tid: 'T1499.002', name: 'Service Exhaustion' },
          { tid: 'T1499.003', name: 'Application Exhaustion' },
          { tid: 'T1499.004', name: 'Application or System Exploitation' }
        ]
      },
      {
        tid: 'T1531',
        name: 'Account Access Removal'
      },
      {
        tid: 'T1657',
        name: 'Financial Theft'
      },
      {
        tid: 'T1496',
        name: 'Resource Hijacking'
      },
      {
        tid: 'T1495',
        name: 'Damage Firmware'
      },
      {
        tid: 'T1561',
        name: 'Disk Structure Wipe',
        subTechniques: [
          { tid: 'T1561.001', name: 'MBR Wipe' },
          { tid: 'T1561.002', name: 'VBR Wipe' }
        ]
      },
      {
        tid: 'T1480',
        name: 'Execution Guardrails',
        subTechniques: [
          { tid: 'T1480.001', name: 'Environmental Keying' }
        ]
      },
      {
        tid: 'T1484',
        name: 'Group Policy Modification',
        subTechniques: [
          { tid: 'T1484.001', name: 'Domain Policy Modification' },
          { tid: 'T1484.002', name: 'Group Policy Modification' }
        ]
      }
    ]
  }
];

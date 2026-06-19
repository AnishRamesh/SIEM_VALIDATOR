export type ValidationState = 'CORRECT' | 'NEEDS_FIX' | 'UNASSIGNED';

export interface SiemConfig {
  _id: string;
  platformType: string; // e.g., "Palo Alto XSIAM"
  apiEndpoint: string;
  apiId?: string;
  apiPassphraseHash: string; // Masked/Hashed placeholder
  lastSyncedAt: string | null;
}

export interface CorrelationRule {
  _id: string;
  ruleId: string;
  ruleName: string;
  siemSource: string; // e.g., "xyzcomp"
  existingTid: string; // Existing MITRE T-ID (e.g., "T1003.001")
  mappedTechniqueName: string;
  suggestedTid: string | null; // Allow null
  confidenceScore: number | null; // percentage (0-100) or null
  validationState: ValidationState;
  actionsTaken: string;
  dateAdded: string; // ISO string for monthly metrics
  lastUpdated: string; // ISO string
}

export interface TacticCoverage {
  tacticId: string;
  name: string;
  shortName: string;
  currentMonth: number; // percentage
  previousMonth: number; // percentage
}

export interface TacticCoverageSnapshot {
  _id: string;
  snapshotMonth: string; // "YYYY-MM"
  tactics: {
    [tacticId: string]: {
      currentMonth: number;
      previousMonth: number;
    };
  };
}

export interface SubTechniqueDetails {
  tid: string;
  name: string;
  covered: boolean;
  rulesMapped: string[];
}

export interface TechniqueDetails {
  tid: string;
  name: string;
  covered: boolean;
  rulesMapped: string[]; // Rule IDs mapping to this technique
  subTechniques?: SubTechniqueDetails[];
}

export interface TacticDetailResponse {
  tacticId: string;
  name: string;
  coveredCount: number;
  uncoveredCount: number;
  totalCount: number;
  techniques: TechniqueDetails[];
}

export interface DashboardStats {
  totalRules: number;
  correctRules: number;
  needsFixRules: number;
  unassignedRules: number;
  missingMappingRules?: number;
  missingTechniqueRules?: number;
  missingSubTechniqueRules?: number;
  averageConfidence: number | null;
}

export interface SystemStatus {
  connected: boolean;
  platform: string;
  ruleEngineVersion: string;
  databaseStatus: string;
  lastSyncTime: string | null;
  ruleCount: number;
  apiEndpoint?: string;
  apiId?: string;
  mongoConnected?: boolean;
  mongoDbStatus?: string;
}

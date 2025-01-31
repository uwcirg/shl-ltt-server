export interface HealthLinkFile {
  contentType: string;
  content: Uint8Array;
}

export interface HealthLinkEndpoint {
  id?: string;
  refreshTime?: string;
  endpointUrl: string;
  config: {
    key: string;
    clientId: string;
    clientSecret: string;
    tokenEndpoint: string;
    refreshToken: string;
  };
  accessTokenResponse?: {
    access_token: string;
    scope: string;
    refresh_token?: string;
  };
}

export interface HealthLinkConfig {
  passcode?: string;
  exp?: number;
  userId?: string;
  sessionId?: string;
}

export interface HealthLink {
  config: HealthLinkConfig;
  active: boolean;
  id: string;
  userId?: string;
  sessionId?: string;
  created: number;
  managementToken?: string;
  passcodeFailuresRemaining?: number;
}

export interface HealthLinkManifestRequest {
  recipient: string;
  passcode?: string;
  embeddedLengthMax?: number;
}

export interface SHLinkManifestFile {
  contentType: 'application/fhir+json' | 'application/smart-health-card' | 'application/smart-api-access';
  location: string;
}

export interface SHLinkManifest {
  files: SHLinkManifestFile[];
}

export interface SHLinkAddFileRequest {
  id: string;
  files: HealthLinkFile[];
}

export interface SHLDecoded {
  url: string;
  flag: string;
  key: string & { length: 43 };
  exp?: number;
  label?: string;
}

type Action = 'create' | 'read' | 'update' | 'delete' | 'execute' | 'login' | 'logout';
type Severity = 'critical' | 'error' | 'warning' | 'info' | 'debug';

export interface LogMessage {
  version: string;
  severity: Severity;
  action: Action;
  occurred?: string; // datetime of event
  subject?: string; // subject id
  agent?: {
    ip_address?: string;
    user_agent?: string;
    type?: string; // e.g. system, user
    who?: string; // agent id
  };
  source?: {
    observer?: string; // system url
    type?: string; // system/project name
    version?: string; // system version
  }
  entity?: {
    detail?: {[key: string] : string}; // additional info
    query?: string; // query parameters
  };
  outcome?: string; // failure or warning details
}

export interface LogMessageSimple extends Partial<LogMessage> {
  action: Action;
}

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
  created: string;
  managementToken?: string;
  passcodeFailuresRemaining: number;
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

export interface LogMessageSimple {
  "message": string;
  "tags"?: string[];
  "level"?: "INFO" | "ERROR" | "WARN" | "DEBUG";
  "subject"?: string;
  "user"?: string;
  "name"?: string;
  "deployment"?: "dev" | "test" | "demo" | "stage" | "prod";
  "system-type"?: string;
  "system-url"?: string;
  "session-id"?: string;
}
export interface LogMessage {
  "event_version": string;
  "asctime": string;
  "name": string;
  "level": "INFO" | "ERROR" | "WARN" | "DEBUG";
  "deployment": "dev" | "test" | "demo" | "stage" | "prod";
  "system-url": string;
  "system-type": string;
  "user": string;
  "subject": string;
  "tags": string[];
  "message": string;
  "session-id": string;
  "ip-address": string;
  "user-agent": string;
}
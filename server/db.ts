import env from './config.ts';
import { base64url, queryString, sqlite } from './deps.ts';
import { clientConnectionListener } from './routers/api.ts';
import * as types from './types.ts';
import { randomStringWithEntropy } from './util.ts';

const { DB } = sqlite;

const db = new DB('./db/vaxx.db');
const schema = await Deno.readTextFile('./schema.sql');
schema.split(/\n\n/).forEach((q) => {
  try {
    db.execute(q);
  } catch (e) {
    if (!q.match('ok_to_fail')) throw e;
  }
});

async function updateAccessToken(endpoint: types.HealthLinkEndpoint) {
  const accessTokenRequest = await fetch(endpoint.config.tokenEndpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${endpoint.config.clientId}:${endpoint.config.clientSecret}`)}`,
    },
    body: queryString.stringify({ grant_type: 'refresh_token', refresh_token: endpoint.config.refreshToken }),
  });
  const accessTokenResponse = await accessTokenRequest.json();


  endpoint.accessTokenResponse = accessTokenResponse;
  if (endpoint?.accessTokenResponse?.refresh_token) {
    endpoint.config.refreshToken = endpoint.accessTokenResponse.refresh_token;
    delete endpoint.accessTokenResponse.refresh_token;
  }
  const TOKEN_LIFETIME_SECONDS = 300;
  endpoint.refreshTime = new Date(new Date().getTime() + TOKEN_LIFETIME_SECONDS * 1000).toISOString();
}

export const DbLinks = {
  create(config: types.HealthLinkConfig) {
    let { userId, sessionId, ...configSansUserAndSession } = config;

    const link = {
      config: configSansUserAndSession,
      id: randomStringWithEntropy(32),
      userId: userId,
      sessionId: sessionId,
      managementToken: randomStringWithEntropy(32),
      created: new Date().getTime() / 1000,
      active: true,
    };
    db.query(
      `INSERT INTO shlink (id, user_id, session_id, management_token, active, created, config_exp, config_passcode)
      values (:id, :userId, :sessionId, :managementToken, :active, :created, :exp, :passcode)`,
      {
        id: link.id,
        userId: link.userId,
        sessionId: link.sessionId,
        managementToken: link.managementToken,
        active: link.active,
        created: link.created,
        exp: link.config.exp,
        passcode: link.config.passcode,
      }
    );

    return link;
  },
  updateConfig(linkId:string, config: types.HealthLinkConfig) {
    try{
      db.query(`UPDATE shlink set config_passcode=:passcode, config_exp=:exp, session_id=:sessionId where id=:id`,
    {
      id: linkId,
      exp: config.exp,
      passcode: config.passcode,
      sessionId: config.sessionId
    });
    }catch(e){
      console.log(e);
      return false;
    }
    return true;
  },
  deactivate(shl: types.HealthLink, managementToken: string): boolean {
    db.query(`UPDATE shlink set active=false where id=? and management_token=?`, [shl.id, managementToken]);
    return true;
  },
  reactivate(linkId: string, managementToken: string): boolean {
    db.query(`UPDATE shlink set active=true, passcode_failures_remaining=5 where id=? and management_token=?`, [linkId, managementToken]);
    return true;
  },
  linkExists(linkId: string): boolean {
    return Boolean(db.query(`SELECT * from shlink where id=? and active=1`, [linkId]));
  },
  getManagedShl(linkId: string, managementToken: string): types.HealthLink {
    const linkRow = db
      .prepareQuery(`SELECT * from shlink where id=? and management_token=?`)
      .oneEntry([linkId, managementToken]);

    return {
      id: linkRow.id as string,
      passcodeFailuresRemaining: linkRow.passcode_failures_remaining as number,
      active: Boolean(linkRow.active) as boolean,
      userId: linkRow.user_id as string,
      sessionId: linkRow.session_id as string,
      created: linkRow.created as number,
      managementToken: linkRow.management_token as string,
      config: {
        exp: linkRow.config_exp as number,
        passcode: linkRow.config_passcode as string,
      },
    };
  },
  getTokenOwner(managementToken: string): string | undefined {
    const linkRow = db.prepareQuery(`SELECT user_id from shlink where management_token=?`).oneEntry([managementToken]);
    return linkRow.user_id as string;
  },
  getUserShl(userId: string): types.HealthLink | undefined {
    try {
      const linkRow = db
        .prepareQuery(`SELECT * from shlink where user_id=? and active=1 order by created desc limit 1`)
        .oneEntry([userId]);
      return {
        id: linkRow.id as string,
        passcodeFailuresRemaining: linkRow.passcode_failures_remaining as number,
        active: Boolean(linkRow.active) as boolean,
        userId: linkRow.user_id as string,
        sessionId: linkRow.session_id as string,
        created: linkRow.created as number,
        managementToken: linkRow.management_token as string,
        config: {
          exp: linkRow.config_exp as number,
          passcode: linkRow.config_passcode as string,
        },
      };
    } catch (e) {
      console.warn(e);
      return undefined;
    }
  },
  getShlInternal(linkId: string): types.HealthLink {
    const linkRow = db.prepareQuery(`SELECT * from shlink where id=?`).oneEntry([linkId]);
    return {
      id: linkRow.id as string,
      passcodeFailuresRemaining: linkRow.passcode_failures_remaining as number,
      active: Boolean(linkRow.active) as boolean,
      userId: linkRow.user_id as string,
      sessionId: linkRow.session_id as string,
      created: linkRow.created as number,
      managementToken: linkRow.management_token as string,
      config: {
        exp: linkRow.config_exp as number,
        passcode: linkRow.config_passcode as string,
      },
    };
  },
  async addFile(linkId: string, file: types.HealthLinkFile): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', file.content);
    const hashEncoded = base64url.encode(hash);
    db.query(`insert or ignore into cas_item(hash, content) values(:hashEncoded, :content)`, {
      hashEncoded,
      content: file.content,
    });

    db.query(
      `insert into shlink_file(shlink, content_type, content_hash) values (:linkId, :contentType, :hashEncoded)`,
      {
        linkId,
        contentType: file.contentType,
        hashEncoded,
      },
    );

    return hashEncoded;
  },
  async deleteFile(linkId: string, content: Uint8Array) {
    const hash = await crypto.subtle.digest('SHA-256', content);
    const hashEncoded = base64url.encode(hash);

    db.query(
      `delete from shlink_file where shlink = :linkId and content_hash = :hashEncoded`,
      {
        linkId,
        hashEncoded,
      }
    );

    // db.query(`delete from cas_item where hash = :hashEncoded and content = :content`,
    // {
    //   hashEncoded,
    //   content: file.content,
    // });

    return hashEncoded;
  },
  async deleteAllFiles(linkId: string) {

    db.query(
      `delete from shlink_file where shlink = :linkId`,
      {
        linkId
      }
    );

    return true;
  },
  async addEndpoint(linkId: string, endpoint: types.HealthLinkEndpoint): Promise<string> {
    const id = randomStringWithEntropy(32);

    await updateAccessToken(endpoint);
    db.query(
      `insert into shlink_endpoint(
          id, shlink, endpoint_url,
          config_key, config_client_id, config_client_secret, config_token_endpoint, config_refresh_token, refresh_time,
          access_token_response)
        values (
          :id, :linkId, :endpointUrl, :key, :clientId, :clientSecret, :tokenEndpoint, :refreshToken, :refreshTime, :accessTokenResponse
        )`,
      {
        id,
        linkId,
        endpointUrl: endpoint.endpointUrl,
        key: endpoint.config.key,
        clientId: endpoint.config.clientId,
        clientSecret: endpoint.config.clientSecret,
        tokenEndpoint: endpoint.config.tokenEndpoint,
        refreshTime: endpoint.refreshTime,
        refreshToken: endpoint.config.refreshToken,
        accessTokenResponse: JSON.stringify(endpoint.accessTokenResponse),
      },
    );

    return id;
  },
  async saveEndpoint(endpoint: types.HealthLinkEndpoint): Promise<boolean> {
    db.query(`update shlink_endpoint set config_refresh_token=?, refresh_time=?, access_token_response=? where id=?`, [
      endpoint.config.refreshToken,
      endpoint.refreshTime,
      JSON.stringify(endpoint.accessTokenResponse),
      endpoint.id,
    ]);
    return await true;
  },
  getManifestFiles(linkId: string, embeddedLengthMax?: number) {
    embeddedLengthMax = Math.min(env.EMBEDDED_LENGTH_MAX, embeddedLengthMax ?? Infinity);
    const files = db.queryEntries<{ content_type: string; content_hash: string, content?: Uint8Array }>(
      `select
      content_type,
      content_hash,
      (case when length(cas_item.content) <= ${embeddedLengthMax} then cas_item.content else NULL end) as content
      from shlink_file
      join cas_item on shlink_file.content_hash=cas_item.hash
      where shlink=?`,
      [linkId],
    );
    return files.map((r) => ({
      contentType: r.content_type as types.SHLinkManifestFile['contentType'],
      hash: r.content_hash,
      content: r.content
    }));
  },
  getManifestEndpoints(linkId: string) {
    const endpoints = db.queryEntries<{ id: string }>(`select id from shlink_endpoint where shlink=?`, [linkId]);
    return endpoints.map((e) => ({
      contentType: 'application/smart-api-access',
      id: e.id,
    }));
  },
  async getEndpoint(linkId: string, endpointId: string): Promise<types.HealthLinkEndpoint> {
    const endpointRow = db
      .prepareQuery<
        Array<unknown>,
        {
          id: string;
          endpoint_url: string;
          config_key: string;
          config_client_id: string;
          config_client_secret: string;
          config_token_endpoint: string;
          config_refresh_token: string;
          refresh_time: string;
          access_token_response: string;
        }
      >(
        `select
        id, endpoint_url,
        config_key, config_client_id, config_client_secret, config_token_endpoint, config_refresh_token,
        refresh_time, access_token_response
      from shlink_endpoint where shlink=? and id=?`,
      )
      .oneEntry([linkId, endpointId]);

    const endpoint: types.HealthLinkEndpoint = {
      id: endpointRow.id,
      endpointUrl: endpointRow.endpoint_url,
      config: {
        key: endpointRow.config_key,
        clientId: endpointRow.config_client_id,
        clientSecret: endpointRow.config_client_secret,
        refreshToken: endpointRow.config_refresh_token,
        tokenEndpoint: endpointRow.config_token_endpoint,
      },
      refreshTime: endpointRow.refresh_time,
      accessTokenResponse: JSON.parse(endpointRow.access_token_response),
    };

    if (new Date(endpoint.refreshTime!).getTime() < new Date().getTime()) {
      await updateAccessToken(endpoint);
      await DbLinks.saveEndpoint(endpoint);
    }

    return endpoint;
  },

  getFile(shlId: string, contentHash: string): types.HealthLinkFile {
    const fileRow = db.queryEntries<{ content_type: string; content: Uint8Array }>(
      `select content_type, content from shlink_file f join cas_item c on f.content_hash=c.hash
      where f.shlink=:shlId and f.content_hash=:contentHash`,
      { shlId, contentHash },
    );

    return {
      content: fileRow[0].content,
      contentType: fileRow[0].content_type,
    };
  },
  recordAccess(shlId: string, recipient: string) {
    const q = db.prepareQuery(`insert into  shlink_access(shlink, recipient) values (?, ?)`);
    q.execute([shlId, recipient]);

    clientConnectionListener({
      shlId,
      recipient,
    });
  },
  recordPasscodeFailure(shlId: string) {
    const q = db.prepareQuery(`update shlink set passcode_failures_remaining = passcode_failures_remaining - 1 where id=?`);
    q.execute([shlId]);
  },
};

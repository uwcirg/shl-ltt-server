import env from '../config';
import { jose, oak } from '../deps';
import * as db from '../db';
import * as types from '../types';
import { randomStringWithEntropy } from '../util';

type SubscriptionTicket = string;
type SubscriptionSet = string[];
const subscriptionTickets: Map<SubscriptionTicket, SubscriptionSet> = new Map();

const accessLogSubscriptions: Map<string, oak.ServerSentEventTarget[]> = new Map();
interface ClientConnectionMessage {
  shlId: string;
  recipient: string;
}
export const clientConnectionListener = (cxn: ClientConnectionMessage) => {
  (accessLogSubscriptions.get(cxn.shlId) || []).forEach((t, _i) => {
    t.dispatchEvent(new oak.ServerSentEvent('connection', cxn));
  });
};

interface ManifestAccessTicket {
  shlId: string;
}
const manifestAccessTickets: Map<string, ManifestAccessTicket> = new Map();

function log(content: types.LogMessageSimple, context) {
  let defaults: types.LogMessage = {
    "event_version": "1",
    "asctime": new Date().toISOString(),
    "name": "shl-ltt-server",
    "level": "INFO",
    "deployment": env.DEPLOYMENT,
    "system-type": "server",
    "system-url": env.PUBLIC_URL,
    "user": "",
    "subject": "",
    "tags": [],
    "message": "",
    "session-id": "",
    "ip-address": context.request.ip,
    "user-agent": context.request.userAgent,
  }

  const logMessage: types.LogMessage = { ...defaults, ...content };
  logMessage.tags.push(`${context.request.method} ${context.request.url}`);
  console.log(JSON.stringify(logMessage));
}

export const shlApiRouter = new oak.Router()
  .post('/log', async (context: oak.Context) => {
    const content: types.LogMessageSimple = await context.request.body({ type: 'json' }).value;
    if (content.message) {
      let defaults = {
        "name": "external",
        "system-type": "client",
      };
      let logMessage = { ...defaults, ...content };
      log(logMessage, context);
      return;
    }
    context.response.status = 400;
    context.response.headers.set('content-type', 'application/json');
    return (context.response.body = { message: "Log content must contain a message." });
  })
  .post('/shl', async (context: oak.Context) => {
    const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
    const newLink = db.DbLinks.create(config);
    console.log("Created link " + newLink.id);
    log({
      message: `Created new SHL ${newLink.id} for session ${newLink.sessionId}`,
      level: "INFO",
      tags: ["new-link", `shl-${newLink.id}`, `session-${newLink.sessionId}`],
    }, context);
    return (context.response.body = {
      ...newLink,
      files: undefined,
      config: undefined,
    });
  })
  .post('/shl/:shlId', async (context: oak.Context) => {
    const config: types.HealthLinkManifestRequest = await context.request.body({ type: 'json' }).value;
    const embeddedLengthMax = Math.min(env.EMBEDDED_LENGTH_MAX, config.embeddedLengthMax !== undefined ? config.embeddedLengthMax : Infinity);

    let shl: types.HealthLink;
    try {
      shl = db.DbLinks.getShlInternal(context.params.shlId);
    } catch {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated."};
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (!shl?.active) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (shl.config.passcode && !("passcode" in config)) {
      context.response.status = 401;
      context.response.body = {
        message: "Password required",
        remainingAttempts: shl.passcodeFailuresRemaining
      }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (shl.config.passcode && shl.config.passcode !== config.passcode) {
      db.DbLinks.recordPasscodeFailure(shl.id);
      context.response.status = 401;
      context.response.body = {
        message: "Incorrect password",
        remainingAttempts: shl.passcodeFailuresRemaining - 1
      };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const ticket = randomStringWithEntropy(32);
    manifestAccessTickets.set(ticket, {
      shlId: shl.id,
    });
    setTimeout(() => {
      manifestAccessTickets.delete(ticket);
    }, 60000);
    db.DbLinks.recordAccess(shl.id, config.recipient);

    context.response.headers.set('expires', new Date().toUTCString());
    context.response.headers.set('content-type', 'application/json');
    return (context.response.body = {
      files: db.DbLinks.getManifestFiles(shl.id, embeddedLengthMax)
        .map((f, _i) => ({
          contentType: f.contentType,
          embedded: f.content?.length ? new TextDecoder().decode(f.content) : undefined,
          location: `${env.PUBLIC_URL}/api/shl/${shl.id}/file/${f.hash}?ticket=${ticket}`,
        }))
        .concat(
          db.DbLinks.getManifestEndpoints(shl.id).map((e) => ({
            contentType: 'application/smart-api-access',
            embedded: undefined,
            location: `${env.PUBLIC_URL}/api/shl/${shl.id}/endpoint/${e.id}?ticket=${ticket}`,
          })),
        ),
    });
  })
  .put('/shl/:shlId', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const config = await context.request.body({ type: 'json' }).value;
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    shl.config.exp = config.exp ?? shl.config.exp;
    shl.config.passcode = config.passcode ?? shl.config.passcode;
    const updated = db.DbLinks.updateConfig(context.params.shlId, config)!;
    if (!updated) {
      return (context.response.status = 500);
    }
    const updatedShl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    delete updatedShl.managementToken;
    context.response.body = updatedShl;
    context.response.headers.set('content-type', 'application/json');
  })
  .get('/shl/:shlId/active', (context) => {
    const shl = db.DbLinks.getShlInternal(context.params.shlId);
    if (!shl) {
      context.response.status = 404;
      context.response.body = { message: `Deleted` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const isActive = (shl && shl.active);
    console.log(context.params.shlId + " active: " + isActive);
    context.response.body = isActive;
    context.response.headers.set('content-type', 'application/json');
    return;
  })
  .put('/shl/:shlId/reactivate', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const success = db.DbLinks.reactivate(context.params.shlId, managementToken)!;
    console.log("Reactivated " + context.params.shlId + ": " + success);
    context.response.headers.set('content-type', 'application/json');
    return (context.response.body = success);
  })
  .get('/user/:userId', async (context: oak.Context) => {
    const shl = db.DbLinks.getUserShl(context.params.userId)!;
    if (!shl) {
      console.log(`Can't find SHLink for user ` + context.params.userId);
      return;
    }
    return (context.response.body = shl);
  })
  .get('/shl/:shlId/file/:fileIndex', (context) => {
    const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
    if (!ticket) {
      console.log('Cannot request SHL without a valid ticket');
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (ticket.shlId !== context.params.shlId) {
      console.log('Ticket is not valid for ' + context.params.shlId);
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const file = db.DbLinks.getFile(context.params.shlId, context.params.fileIndex);
    context.response.headers.set('content-type', 'application/jose');
    context.response.body = file.content;
  })
  .get('/shl/:shlId/endpoint/:endpointId', async (context: oak.Context) => {
    const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
    if (!ticket) {
      console.log('Cannot request SHL without a valid ticket');
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (ticket.shlId !== context.params.shlId) {
      console.log('Ticket is not valid for ' + context.params.shlId);
      context.response.status = 401;
      context.response.body = { message: "Unauthorized" };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const endpoint = await db.DbLinks.getEndpoint(context.params.shlId, context.params.endpointId);
    context.response.headers.set('content-type', 'application/jose');
    const payload = JSON.stringify({
      aud: endpoint.endpointUrl,
      ...endpoint.accessTokenResponse,
    });
    const encrypted = await new jose.CompactEncrypt(new TextEncoder().encode(payload))
      .setProtectedHeader({
        alg: 'dir',
        enc: 'A256GCM',
      })
      .encrypt(jose.base64url.decode(endpoint.config.key));
    return (context.response.body = encrypted);
  })
  .post('/shl/:shlId/file', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const newFileBody = await context.request.body({ type: 'bytes' });

    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const newFile = {
      contentType: context.request.headers.get('content-type')!,
      content: await newFileBody.value,
    };

    const added = db.DbLinks.addFile(shl.id, newFile);
    return (context.response.body = {
      ...shl,
      added,
    });
  })
  .delete('/shl/:shlId/file/all', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const currentFileBody = await context.request.body({type: 'bytes'});

    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken);
    if (!shl) {
      throw new Error(`Can't manage SHLink ` + context.params.shlId);
    }

    const deleted = db.DbLinks.deleteAllFiles(shl.id);
    return (context.response.body = {
      ...shl,
      deleted,
    });
  })
  .delete('/shl/:shlId/file', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const currentFileBody = await context.request.body({type: 'bytes'});
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    
    const deleted = db.DbLinks.deleteFile(shl.id, await currentFileBody.value);
    context.response.headers.set('content-type', 'application/json');
    return (context.response.body = {
      ...shl,
      deleted,
    });
  })
  .post('/shl/:shlId/endpoint', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const config: types.HealthLinkEndpoint = await context.request.body({ type: 'json' }).value;

    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      context.response.status = 401;
      context.response.body = { message: `Unauthorized` };
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const added = await db.DbLinks.addEndpoint(shl.id, config);
    console.log("Added", added)
    return (context.response.body = {
      ...shl,
      added,
    });
  })
  .delete('/shl/:shlId', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist or has been deactivated." };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    try {
      const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
      if (!shl) {
        context.response.status = 401;
        context.response.body = { message: `Unauthorized` };
        context.response.headers.set('content-type', 'application/json');
        return;
      }
      const deactivated = db.DbLinks.deactivate(shl);
      return (context.response.body = deactivated);
    } catch {
      context.response.status = 404;
      context.response.body = { message: "SHL does not exist" };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
  })
  .post('/subscribe', async (context: oak.Context) => {
    const shlSet: { shlId: string; managementToken: string }[] = await context.request.body({ type: 'json' }).value;
    const managedLinks = shlSet.map((req) => db.DbLinks.getManagedShl(req.shlId, req.managementToken));

    const ticket = randomStringWithEntropy(32, 'subscription-ticket-');
    subscriptionTickets.set(
      ticket,
      managedLinks.map((l) => l.id),
    );
    setTimeout(() => {
      subscriptionTickets.delete(ticket);
    }, 10000);
    return (context.response.body = { subscribe: `${env.PUBLIC_URL}/api/subscribe/${ticket}` });
  })
  .get('/subscribe/:ticket', (context) => {
    const validForSet = subscriptionTickets.get(context.params.ticket);
    if (!validForSet) {
      throw 'Invalid ticket for SSE subscription';
    }

    const target = context.sendEvents();
    for (const shl of validForSet) {
      if (!accessLogSubscriptions.has(shl)) {
        accessLogSubscriptions.set(shl, []);
      }
      accessLogSubscriptions.get(shl)!.push(target);
      target.dispatchEvent(new oak.ServerSentEvent('status', db.DbLinks.getShlInternal(shl)));
    }

    const keepaliveInterval = setInterval(() => {
      target.dispatchEvent(new oak.ServerSentEvent('keepalive', JSON.stringify({ shlCount: validForSet.length })));
    }, 15000);

    target.addEventListener('close', () => {
      clearInterval(keepaliveInterval);
      for (const shl of validForSet) {
        const idx = accessLogSubscriptions.get(shl)!.indexOf(target);
        accessLogSubscriptions.get(shl)!.splice(idx, 1);
      }
    });
  });

/*
  .post('/register', (context) => {
  })
  /*
    files: DbLinks.fileNames(client.shlink).map(
            (f, _i) => ({contentType: f.contentType, location: `${env.PUBLIC_URL}/api/shl/${client.shlink}/file/${f}`}),
    ),

  */

import env from '../config.ts';
import { jose, oak } from '../deps.ts';
import * as db from '../db.ts';
import * as types from '../types.ts';
import { randomStringWithEntropy } from '../util.ts';

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

function applyLogFallbacks(logMessage: types.LogMessageSimple, defaults: Partial<types.LogMessage>) {
  if (logMessage.entity) {
    logMessage.entity.detail = {...(defaults.entity?.detail ?? {}), ...(logMessage.entity?.detail ?? {})}; 
  }
  logMessage.entity = {...defaults.entity, ...logMessage.entity};
  logMessage.source = {...defaults.source, ...logMessage.source};
  logMessage.agent = {...defaults.agent, ...logMessage.agent};
  return {...defaults, ...logMessage};
}

function log(context: oak.Context, msg: types.LogMessageSimple, shl?: types.HealthLink) {  
  let logMessage: types.LogMessage = {
    version: "3.0",
    severity: "info",
    action: msg.action,
    occurred: new Date().toISOString(),
    subject: shl?.userId,
    agent: {
      ip_address: context.request.ip,
      type: "user", // e.g. system, user
      who: shl?.userId,
      user_agent: context.request.user_agent ?? context.request.headers.get('user-agent')
    },
    source: {
      observer: env.PUBLIC_URL, // system url
      type: "shl-ltt-server", // system/project name
      version: env.APP_VERSION_STRING, // system version
    },
    entity: {
      detail: {
        shl: shl?.id ?? "",
        shl_session: shl?.sessionId ?? "",
        url: context.request.url.toString(),
        method: context.request.method,
      }
    }
  };

  logMessage = (msg ? applyLogFallbacks(msg, logMessage) : logMessage) as types.LogMessage;
  console.log(JSON.stringify(logMessage));
}

export const shlApiRouter = new oak.Router()
  .post('/log', async (context: oak.Context) => {
    const content: types.LogMessageSimple = await context.request.body({ type: 'json' }).value;
    if (!content.action) {
      context.response.status = 400;
      context.response.headers.set('content-type', 'application/json');
      return (context.response.body = { message: "Log content must contain a message." });
    }

    let defaults: Partial<types.LogMessage> = {
      source: {
        type: "external-client"
      }
    };
    const logMessage = applyLogFallbacks(content, defaults);
    log(context, logMessage);
  })
  .post('/shl', async (context: oak.Context) => {
    const config: types.HealthLinkConfig = await context.request.body({ type: 'json' }).value;
    const newLink = db.DbLinks.create(config);
    console.log("Created link " + newLink.id);
    log(context, {
      action: "create",
      entity: { detail: {
        action: `Create shl '${newLink.id}' for user '${newLink.userId}'`,
      }}
    }, newLink);
    return (context.response.body = {
      ...newLink,
      files: undefined,
      config: undefined,
    });
  })
  .post('/shl/:shlId', async (context: oak.Context) => {
    const config: types.HealthLinkManifestRequest = await context.request.body({ type: 'json' }).value;
    const embeddedLengthMax = Math.min(env.EMBEDDED_LENGTH_MAX, config.embeddedLengthMax ?? Infinity);
    if (!config.recipient) {
      let status = 400;
      let message = "Recipient not specified in request body.";
      log(context, {
        action: "create",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        entity: { detail: {
          action: `Manifest request for shl '${context.params.shlId}'`,
          shl: context.params.shlId
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message};
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    let shl: types.HealthLink;
    try {
      shl = db.DbLinks.getShlInternal(context.params.shlId);
    } catch {
      let status = 404;
      let message = "SHL does not exist or has been deactivated.";
      log(context, {
        action: "create",
        severity: "error",
        agent: {
          who: config.recipient
        },
        entity: { detail: {
          action: `Manifest request for shl '${context.params.shlId}'`,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message};
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (!shl?.active) {
      let status = 404;
      let message = "SHL does not exist or has been deactivated.";
      log(context, {
        action: "create",
        severity: "error",
        agent: {
          who: config.recipient
        },
        entity: { detail: {
          action: `Manifest request for shl '${context.params.shlId}'`,
        }},
        outcome: `${status} ${message}`,
      }, shl);
      context.response.status = status;
      context.response.body = { message: message };
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (shl.config.passcode && !("passcode" in config)) {
      let status = 401;
      let message = "Password required";
      let remainingAttempts = shl.passcodeFailuresRemaining;
      log(context, {
        action: "create",
        severity: "error",
        agent: {
          who: config.recipient
        },
        entity: { detail: {
          action: `Manifest request for shl '${context.params.shlId}'`,
          remainingAttempts: String(remainingAttempts)
        } },
        outcome: `${status} ${message}`,
      }, shl);
      context.response.status = status;
      context.response.body = {
        message: message,
        remainingAttempts: remainingAttempts
      }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    if (shl.config.passcode && shl.config.passcode !== config.passcode) {
      db.DbLinks.recordPasscodeFailure(shl.id);
      let status = 401;
      let message = "Incorrect password";
      let remainingAttempts = shl.passcodeFailuresRemaining ? shl.passcodeFailuresRemaining - 1 : 0;
      log(context, {
        action: "create",
        severity: "error",
        entity: { detail: {
          action: `Manifest request for shl '${context.params.shlId}'`,
          remainingAttempts: String(remainingAttempts)
        } },
        outcome: `${status} ${message}`,
      }, shl);
      context.response.status = status;
      context.response.body = {
        message: message,
        remainingAttempts: remainingAttempts
      }
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

    log(context, {
      action: "create",
      entity: { detail: {
        action: `Manifest request for shl '${context.params.shlId}'`,
        recipient: config.recipient,
        ticket: ticket
      } },
    }, shl);

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
    let userId = db.DbLinks.getTokenOwner(managementToken);

    if (!config.sessionId) {
      let status = 400;
      let message = "Missing session_id";
      log(context, {
        action: "update",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: userId
        },
        entity: { detail: {
          action: `Update config for shl '${context.params.shlId}'`,
          config: JSON.stringify(config),
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (!db.DbLinks.linkExists(context.params.shlId)) {
      let status = 404;
      let message = "SHL does not exist or has been deactivated.";
      log(context, {
        action: "update",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: userId
        },
        entity: { detail: {
          action: `Update config for shl '${context.params.shlId}'`,
          config: JSON.stringify(config),
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "update",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: userId
        },
        entity: { detail: {
          action: `Update config for shl '${context.params.shlId}'`,
          config: JSON.stringify(config),
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    shl.config.exp = config.exp ?? shl.config.exp;
    shl.config.passcode = config.passcode ?? shl.config.passcode;
    const updated = db.DbLinks.updateConfig(context.params.shlId, config)!;
    if (!updated) {
      log(context, {
        action: "update",
        severity: "critical",
        entity: { detail: { config: JSON.stringify(Object.keys(config)) } },
        outcome: `Failed to update SHL config`,
      });
      return (context.response.status = 500);
    }
    const updatedShl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    delete updatedShl.managementToken;

    log(context, {
      action: "update",
      entity: { detail: { config: JSON.stringify(Object.keys(config)) } },
    }, shl);

    context.response.body = updatedShl;
    context.response.headers.set('content-type', 'application/json');
  })
  .get('/shl/:shlId/active', (context) => {
    const shl = db.DbLinks.getShlInternal(context.params.shlId);
    if (!shl) {
      let status = 404;
      let message = "SHL does not exist.";
      log(context, {
        action: "read",
        severity: "error",
        entity: { detail: { action: `Read active status for shl '${context.params.shlId}'` } },
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
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
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      let status = 404;
      let message = "SHL does not exist or has been deactivated";
      log(context, {
        action: "update",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          shl: context.params.shlId,
          action: `Reactivate shl '${context.params.shlId}'`
        } },
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    try {
      const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
      if (!shl) {
        let status = 401;
        let message = "Unauthorized";
        log(context, {
          action: "update",
          severity: "error",
          subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
          agent: {
            who: db.DbLinks.getTokenOwner(managementToken)
          },
          entity: { detail: {
            shl: context.params.shlId,
            shl_session: db.DbLinks.getShlInternal(context.params.shlId)?.sessionId ?? "unknown",
            action: `Reactivate shl '${context.params.shlId}'`
          } },
          outcome: `${status} ${message}`,
        });
        context.response.status = status;
        context.response.body = { message: message }
        context.response.headers.set('content-type', 'application/json');
        return;
      }
      const reactivated = db.DbLinks.reactivate(context.params.shlId, managementToken)!;
      log(context, {
        action: "update",
        entity: { detail: { action: `Reactivated shl '${context.params.shlId}'` } },
      }, shl);
      return (context.response.body = reactivated);
    } catch {
      let status = 404;
      let message = "SHL does not exist";
      log(context, {
        action: "update",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          shl: context.params.shlId,
          action: `Reactivate shl '${context.params.shlId}'`
        } },
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
  })
  .get('/user/:userId', async (context: oak.Context) => {
    const shl = db.DbLinks.getUserShl(context.params.userId)!;
    if (!shl) {
      log(context, {
        action: "read",
        severity: "warning",
        entity: { detail: { action: `Get shl for user '${context.params.userId}'` } },
        outcome: `SHL not found for user '${context.params.userId}'`,
      }, {userId: context.params.userId} as types.HealthLink);
      return;
    }
    log(context, {
      action: "read"
    }, shl);
    return (context.response.body = shl);
  })
  .get('/shl/:shlId/file/:fileIndex', (context) => {
    const ticket = manifestAccessTickets.get(context.request.url.searchParams.get('ticket')!);
    if (!ticket) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "read",
        severity: "error",
        entity: { detail: {
          action: `Get file '${context.params.fileIndex}' for shl '${context.params.shlId}'`,
          shl: context.params.shlId,
          file: context.params.fileIndex
        } },
        outcome: `${status} ${message}: missing ticket`,
      });
      context.response.status = status;
      context.response.body = {
        message: message
      }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    if (ticket.shlId !== context.params.shlId) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "read",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        entity: { detail: {
          action: `Get file '${context.params.fileIndex}' for shl '${context.params.shlId}'`,
          ticket: context.request.url.searchParams.get('ticket')!,
          shl: context.params.shlId,
          file: context.params.fileIndex
        } },
        outcome: `${status} ${message}: invalid ticket`,
      });
      context.response.status = status;
      context.response.body = {
        message: message
      }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const file = db.DbLinks.getFile(context.params.shlId, context.params.fileIndex);
    
    log(context, {
      action: "read",
      subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
      entity: { detail: {
        action: `Get file '${context.params.fileIndex}' for shl '${context.params.shlId}'`,
        ticket: context.request.url.searchParams.get('ticket')!,
        shl: context.params.shlId,
        file: context.params.fileIndex,
        contentType: file.contentType
      } },
    });

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
      let status = 404;
      let message = "SHL does not exist or has been deactivated";
      log(context, {
        action: "create",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Add file to shl '${context.params.shlId}'`,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "create",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Add file to shl '${context.params.shlId}'`,
          shl: context.params.shlId,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const newFile = {
      contentType: context.request.headers.get('content-type')!,
      content: await newFileBody.value,
    };

    const added = await db.DbLinks.addFile(shl.id, newFile);
    
    log(context, {
      action: "create",
      entity: { detail: {
        action: `Add file '${added}' to shl '${shl.id}'`,
        file: added,
        contentType: newFile.contentType,
      } },
    }, shl);

    return (context.response.body = {
      ...shl,
      added,
    });
  })
  .delete('/shl/:shlId/file/all', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;

    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken);
    if (!shl) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "delete",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Delete all files from shl '${context.params.shlId}'`,
          shl: context.params.shlId,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    try {
      let files = db.DbLinks.getManifestFiles(shl.id);
      let filesToDelete = files.reduce((r, f) => ({ ...r, [f.hash]: f.contentType }), {})
      const deleted = db.DbLinks.deleteAllFiles(shl.id);
      log(context, {
        action: "delete",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Delete all files from shl '${shl.id}'`,
          ...filesToDelete,
        }}
      }, shl);
      return (context.response.body = {
        ...shl,
        deleted: filesToDelete,
      });
    } catch (e) {
      let status = 500;
      let message = "Failed to delete files";
      log(context, {
        action: "delete",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Delete all files from shl '${context.params.shlId}'`,
          shl: context.params.shlId,
          error: JSON.stringify(e, Object.getOwnPropertyNames(e))
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
  })
  .delete('/shl/:shlId/file', async (context: oak.Context) => {
    const managementToken = await context.request.headers.get('authorization')?.split(/bearer /i)[1]!;
    const currentFileBody = await context.request.body({type: 'bytes'});
    if (!db.DbLinks.linkExists(context.params.shlId)) {
      let status = 404;
      let message = "SHL does not exist or has been deactivated";
      log(context, {
        action: "delete",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Delete all files from shl '${context.params.shlId}'`,
          shl: context.params.shlId,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
    if (!shl) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "delete",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Delete all files from shl '${context.params.shlId}'`,
          shl: context.params.shlId,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    let files = db.DbLinks.getManifestFiles(shl.id);
    const deleted = await db.DbLinks.deleteFile(shl.id, await currentFileBody.value);
    let contentType = files.find((f) => f.hash === deleted)?.contentType;
    log(context, {
      action: "delete",
      entity: { detail: {
        action: `Deleted file '${deleted}' from shl '${shl.id}'`,
        file: deleted,
        contentType: contentType
      } }
    }, shl);
    context.response.headers.set('content-type', 'application/json');
    return (context.response.body = {
      ...shl,
      deleted: deleted
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
      let status = 404;
      let message = "SHL does not exist or has been deactivated";
      log(context, {
        action: "delete",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Delete shl '${context.params.shlId}'`,
          shl: context.params.shlId,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
    try {
      const shl = db.DbLinks.getManagedShl(context.params.shlId, managementToken)!;
      if (!shl) {
        let status = 401;
        let message = "Unauthorized";
        log(context, {
          action: "delete",
          severity: "error",
          subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
          agent: {
            who: db.DbLinks.getTokenOwner(managementToken)
          },
          entity: { detail: {
            action: `Deactivate shl '${context.params.shlId}'`,
            shl: context.params.shlId,
          }},
          outcome: `${status} ${message}`,
        });
        context.response.status = status;
        context.response.body = { message: message }
        context.response.headers.set('content-type', 'application/json');
        return;
      }
      const deactivated = db.DbLinks.deactivate(shl, managementToken);

      log(context, {
        action: "delete",
        entity: { detail: {
          action: `Deactivated shl '${context.params.shlId}'`,
        }}
      }, shl);

      return (context.response.body = deactivated);
    } catch {
      let status = 404;
      let message = "SHL does not exist";
      log(context, {
        action: "delete",
        severity: "error",
        subject: db.DbLinks.getShlInternal(context.params.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(managementToken)
        },
        entity: { detail: {
          action: `Deactivate shl '${context.params.shlId}'`,
          shl: context.params.shlId,
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }
  })
  .post('/subscribe', async (context: oak.Context) => {
    const shlSet: { shlId: string; managementToken: string }[] = await context.request.body({ type: 'json' }).value;
    const managedLinks = shlSet.map((req) => db.DbLinks.getManagedShl(req.shlId, req.managementToken));

    if (managedLinks.some((l) => !l)) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "create",
        severity: "error",
        subject: db.DbLinks.getShlInternal(shlSet[0]?.shlId)?.userId,
        agent: {
          who: db.DbLinks.getTokenOwner(shlSet[0]?.managementToken)
        },
        entity: { detail: {
          action: `Subscribe to shl set`
        }},
        outcome: `${status} ${message}`,
      });
      context.response.status = status;
      context.response.body = { message: message }
      context.response.headers.set('content-type', 'application/json');
      return;
    }

    const ticket = randomStringWithEntropy(32, 'subscription-ticket-');
    subscriptionTickets.set(
      ticket,
      managedLinks.map((l) => l.id),
    );
    setTimeout(() => {
      subscriptionTickets.delete(ticket);
    }, 10000);

    log(context, {
      action: "create",
      entity: { detail: {
        action: `Subscribe to shl set`,
        ...(shlSet.reduce((r, f) => ({ ...r, [f.shlId]: f.managementToken }), {})),
      }}
    }, managedLinks[0]);
    return (context.response.body = { subscribe: `${env.PUBLIC_URL}/api/subscribe/${ticket}` });
  })
  .get('/subscribe/:ticket', (context) => {
    const validForSet = subscriptionTickets.get(context.params.ticket);
    if (!validForSet) {
      let status = 401;
      let message = "Unauthorized";
      log(context, {
        action: "read",
        severity: "error",
        entity: { detail: {
          action: `Access shl set subscription`,
          ticket: context.params.ticket
        } },
        outcome: `${status} ${message}: invalid ticket`,
      });
      context.response.status = status;
      context.response.body = {
        message: message
      }
      context.response.headers.set('content-type', 'application/json');
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

    log(context, {
      action: "read",
      entity: { detail: {
        action: `Update shl set via subscription`,
        ticket: context.params.ticket,
        shls: JSON.stringify(validForSet)
      }}
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

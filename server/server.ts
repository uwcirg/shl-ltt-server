import { Application, Router, send } from 'https://deno.land/x/oak@v10.5.1/mod.ts';
import { oakCors } from 'https://deno.land/x/cors@v1.2.2/mod.ts';
import { encode } from 'https://deno.land/std@0.133.0/encoding/base64url.ts';
import * as jose from 'https://deno.land/x/jose@v4.6.0/index.ts';

const baseUrl = "http://localhost:8000"
const authzUrl = baseUrl + "/authorize"

function randomStringWithEntropy(entropy: number) {
  const b = new Uint8Array(entropy);
  crypto.getRandomValues(b);
  return encode(b.buffer);
}

interface HealthLinkConnection {
  name: string;
  active: boolean;
  jwk: Record<string, unknown>;
  log: {
    url: string;
    date: number;
  };
}

interface HealthLinkFile {
  contentType: string;
  content: Uint8Array;
}

interface SHLinkConfig {
  pin?: string;
  exp?: number;
  encrypted: boolean;
}


interface HealthLink {
  config: SHLinkConfig;
  active: boolean;
  url: string;
  token: string;
  managementToken: string;
  files?: HealthLinkFile[];
  connections: HealthLinkConnection[];
}

const DbLinks = new Map<string, HealthLink>();

function createDbLink(config: SHLinkConfig): HealthLink {
  return {
    config,
    url: authzUrl,
    token: randomStringWithEntropy(32),
    managementToken: randomStringWithEntropy(32),
    active: true,
    files: [],
    connections: [],
  };
}
interface SHLinkAddFileRequest {
  id: string,
  files: HealthLinkFile[]
}


const router = new Router()
  .get('/', async (context) => {
    await send(context, context.request.url.pathname, {
      root: `//home/jmandel/work/vaxx.link/server/static`,
      index: 'index.html',
    });
  })
  .post('/shl', async (context) => {
    const config: SHLinkConfig = await context.request.body({ type: 'json' }).value;
    const newLink = createDbLink(config)
    DbLinks.set(newLink.token, newLink)
    context.response.body =  {
      ...newLink,
      files: undefined
    }
  })
  .get('/shl/:shlId/file/:fileIndex', (context) => {
    // TODO add authz ;-)
    const shl = DbLinks.get(context.params.shlId)!
    const file = shl.files![Number(context.params.fileIndex)] 
    context.response.headers.set("content-type", file.contentType)
    context.response.body = file.content
  })
  .post('/shl/:shlId/file', async (context) => {
    const managementToken = await context.request.headers.get("authorization")?.split(/bearer /i)[1];
    const newFileBody = await context.request.body({type: "bytes"})

    const shl = DbLinks.get(context.params.shlId)!
    if (!shl || managementToken !== shl.managementToken) {
      throw new Error(`Can't manage SHLink ` + context.params.shlId)
    }

    shl.files = shl.files!.concat({
      contentType: context.request.headers.get("content-type")!,
      content: await newFileBody.value
    })

    context.response.body = {
      ...shl,
      files: undefined,
      addedFiles: shl.files.length
    }
  })
  .get('/path', (context) => {
    context.response.body = 'path' + Deno.cwd();
  })
  .get('/links', (context) => {
    context.response.body = Array.from(DbLinks.values());
  })
  .get('/link/:id', (context) => {
    if (context.params && context.params.id && DbLinks.has(context.params.id)) {
      context.response.body = DbLinks.get(context.params.id);
    }
  })
  .get('/jwt', async (context) => {
    const key = await jose.generateKeyPair('ES384');
    context.response.body = {
      jws: await new jose.SignJWT({ a: 1, b: 2 })
        .setIssuer('https://issuer.example.org')
        .setProtectedHeader({ alg: 'ES384' })
        .sign(key.privateKey),
    };
  });

const app = new Application();
app.use(oakCors());
app.use(router.routes());

console.info('CORS-enabled web server listening on port 8000');
await app.listen({ port: parseInt(Deno.env.get('PORT') || '8000') });
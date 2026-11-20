import { getStore } from '@netlify/blobs';

import {

  scryptSync,

  randomBytes,

  timingSafeEqual,

  createHmac,

  randomUUID

} from 'node:crypto';

import seed from '../../seed.json' with { type: 'json' };

const json = (x, status = 200, headers = {}) =>

  new Response(JSON.stringify(x), {

    status,

    headers: {

      'content-type': 'application/json',

      'cache-control': 'no-store',

      'x-content-type-options': 'nosniff',

      ...headers

    }

  });

const env = k => Netlify.env.get(k);

const hash = p => {

  let salt = randomBytes(16).toString('hex');

  return salt + ':' +

    scryptSync(p, salt, 64).toString('hex');

};

const verify = (p, h) => {

  try {

    let [salt, expected] = h.split(':');

    return timingSafeEqual(

      scryptSync(p, salt, 64),

      Buffer.from(expected, 'hex')

    );

  } catch {

    return false;

  }

};

const token = (id, secret) => {

  let payload = Buffer.from(

    JSON.stringify({

      id,

      exp: Date.now() + 12 * 3600000

    })

  ).toString('base64url');

  return payload + '.' +

    createHmac('sha256', secret)

      .update(payload)

      .digest('base64url');

};

const auth = (req, secret) => {

  try {

    let t = req.headers

      .get('cookie')

      ?.match(/(?:^|;\s*)session=([^;]+)/)?.[1];

    if (!t) return null;

    let [p, s] = t.split('.');

    let expected = createHmac('sha256', secret)

      .update(p)

      .digest('base64url');

    if (

      !timingSafeEqual(

        Buffer.from(s),

        Buffer.from(expected)

      )

    ) return null;

    let v = JSON.parse(

      Buffer.from(p, 'base64url')

    );

    return v.exp > Date.now() ? v.id : null;

  } catch {

    return null;

  }

};

const cookie = (t, clear = false) =>

  `session=${t}; Path=/; HttpOnly; Secure; SameSite=Strict; ${

    clear ? 'Max-Age=0' : 'Max-Age=43200'

  }`;

const str = (v, n = 500) =>

  String(v ?? '').slice(0, n);

const userPublic = u => ({

  id: u.id,

  username: u.username,

  role: u.role,

  approved: u.approved

});

const read = async (store, key) =>

  await store.get(key, {

    type: 'json',

    consistency: 'strong'

  });

const write = async (store, key, value) =>

  store.setJSON(key, value);

const list = async (store, prefix) => {

  let keys = [];

  let cursor;

  do {

    let page = await store.list({

      prefix,

      cursor

    });

    keys.push(

      ...page.blobs.map(x => x.key)

    );

    cursor = page.cursor;

  } while (cursor);

  return Promise.all(

    keys.map(k => read(store, k))

  );

};

export default async function(req) {

  try {

    const secret = env('SESSION_SECRET');

    const adminName = env('ADMIN_USERNAME');

    const adminPass = env('ADMIN_PASSWORD');

    if (

      !secret ||

      secret.length < 32 ||

      !adminName ||

      !adminPass ||

      adminPass.length < 12

    ) {

      return json({

        error:

          'Server setup incomplete. Check Netlify environment variables.'

      }, 503);

    }

    const users = getStore('tracker-users');

    const assets = getStore('tracker-assets');

    const activity = getStore('tracker-activity');

    const files = getStore('tracker-files');

    // ADMINISTRATOR ACCOUNT SETUP

    // Automatically synchronise administrator

    // credentials with Netlify settings.

    let admin = await read(users, 'user/admin');

    if (!admin) {

      admin = {

        id: 'admin',

        username: adminName,

        pass: hash(adminPass),

        role: 'admin',

        approved: true

      };

      await write(

        users,

        'user/admin',

        admin

      );

    } else if (

      admin.username !== adminName ||

      !verify(adminPass, admin.pass) ||

      admin.role !== 'admin' ||

      !admin.approved

    ) {

      admin.username = adminName;

      admin.pass = hash(adminPass);

      admin.role = 'admin';

      admin.approved = true;

      await write(

        users,

        'user/admin',

        admin

      );

    }

    // REQUEST DETAILS

    const url = new URL(req.url);

    const action =

      url.searchParams.get('action') || '';

    const id = auth(req, secret);

    const me = id

      ? await read(users, 'user/' + id)

      : null;

    let body = {};

    if (

      req.method === 'POST' &&

      action !== 'upload'

    ) {

      try {

        body = await req.json();

      } catch {

        return json({

          error: 'Invalid JSON'

        }, 400);

      }

    }

    // LOGIN

    if (

      action === 'login' &&

      req.method === 'POST'

    ) {

      const name = str(

        body.username,

        40

      ).toLowerCase();

      const all = await list(

        users,

        'user/'

      );

      const u = all.find(

        u => u.username.toLowerCase() === name

      );

      if (

        !u ||

        !verify(

          str(body.password, 200),

          u.pass

        ) ||

        !u.approved

      ) {

        return json({

          error:

            'Invalid credentials or awaiting approval'

        }, 401);

      }

      return json(

        {

          user: userPublic(u)

        },

        200,

        {

          'set-cookie': cookie(

            token(u.id, secret)

          )

        }

      );

    }

    // REGISTRATION

    if (

      action === 'register' &&

      req.method === 'POST'

    ) {

      const username = str(

        body.username,

        32

      );

      const password = str(

        body.password,

        200

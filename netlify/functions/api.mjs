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
      );

      if (
        !/^[A-Za-z0-9_]{3,32}$/.test(username) ||
        password.length < 12
      ) {
        return json({
          error:
            'Username must be 3-32 letters, numbers or underscores. Password must contain at least 12 characters.'
        }, 400);
      }

      if (
        (await list(users, 'user/')).some(
          u => u.username.toLowerCase() === username.toLowerCase()
        )
      ) {
        return json({
          error: 'Username already exists'
        }, 409);
      }

      let u = {
        id: randomUUID(),
        username,
        pass: hash(password),
        role: 'engineer',
        approved: false
      };

      await write(users, 'user/' + u.id, u);

      return json({
        message: 'Registration received. Await admin approval.'
      });
    }

    if (action === 'logout') {
      return json({ok: true}, 200, {
        'set-cookie': cookie('', true)
      });
    }

    if (!me || !me.approved) {
      return json({error: 'Please log in'}, 401);
    }

    if (action === 'me') {
      return json({user: userPublic(me)});
    }

    if (action === 'assets' && req.method === 'GET') {
      let all = await list(assets, 'asset/');

      if (!all.length) {
        for (let a of seed) {
          await write(assets, 'asset/' + a.id, a);
        }
        all = seed;
      }

      return json({
        assets: all.sort((a, b) => a.id.localeCompare(b.id))
      });
    }

    if (action === 'save' && req.method === 'POST') {
      const assetId = str(body.id, 60);
      const old = await read(assets, 'asset/' + assetId);

      if (!old) {
        return json({error: 'Equipment not found'}, 404);
      }

      const fields = [
        'status', 'location', 'postcode', 'w3w',
        'fuel', 'condition', 'service', 'comment',
        'lat', 'lng'
      ];

      let next = {...old};

      for (let k of fields) {
        if (k in body) {
          next[k] = ['lat', 'lng'].includes(k)
            ? Number(body[k])
            : str(body[k], 1000);
        }
      }

      if (
        !['available', 'ready', 'inuse'].includes(next.status) ||
        !Number.isFinite(next.lat) ||
        !Number.isFinite(next.lng) ||
        Math.abs(next.lat) > 90 ||
        Math.abs(next.lng) > 180
      ) {
        return json({error: 'Invalid status or coordinates'}, 400);
      }

      if (
        next.w3w &&
        !/^(\/\/\/)?[^.\s]+\.[^.\s]+\.[^.\s]+$/.test(next.w3w)
      ) {
        return json({error: 'Invalid what3words address'}, 400);
      }

      next.updated = new Date().toISOString();

      await write(assets, 'asset/' + assetId, next);

      await write(
        activity,
        'log/' + assetId + '/' + Date.now() + '-' + randomUUID(),
        {
          assetId,
          username: me.username,
          event: str(body.event, 100),
          comment: next.comment,
          location: next.location,
          status: next.status,
          created: next.updated
        }
      );

      return json({asset: next});
    }

    if (action === 'history') {
      let assetId = str(url.searchParams.get('id'), 60);

      return json({
        history: (await list(activity, 'log/' + assetId + '/'))
          .sort((a, b) => b.created.localeCompare(a.created))
          .slice(0, 100)
      });
    }

    if (action === 'upload' && req.method === 'POST') {
      let assetId = str(url.searchParams.get('id'), 60);
      let a = await read(assets, 'asset/' + assetId);

      if (!a) {
        return json({error: 'Equipment not found'}, 404);
      }

      let type = req.headers.get('content-type') || '';

      if (![
        'image/jpeg', 'image/png',
        'image/webp', 'application/pdf'
      ].includes(type)) {
        return json({error: 'Only JPG, PNG, WEBP, PDF'}, 400);
      }

      let data = await req.arrayBuffer();

      if (data.byteLength > 3 * 1024 * 1024) {
        return json({error: 'Max file size 3MB'}, 413);
      }

      let key = 'file/' + assetId + '/' + randomUUID();

      await files.set(key, Buffer.from(data), {
        metadata: {
          type,
          username: me.username,
          name: str(url.searchParams.get('name'), 100),
          assetId
        }
      });

      return json({ok: true});
    }

    if (action === 'files') {
      let assetId = str(url.searchParams.get('id'), 60);

      let {blobs} = await files.list({
        prefix: 'file/' + assetId + '/'
      });

      return json({
        files: blobs.map(x => ({
          key: x.key,
          name: x.metadata?.name || 'Attachment',
          username: x.metadata?.username || ''
        }))
      });
    }

    if (action === 'file') {
      let key = str(url.searchParams.get('key'), 200);

      if (!key.startsWith('file/')) {
        return json({error: 'Invalid file'}, 400);
      }

      let {data, metadata} = await files.getWithMetadata(key, {
        type: 'arrayBuffer',
        consistency: 'strong'
      });

      if (!data) {
        return json({error: 'Not found'}, 404);
      }

      return new Response(data, {
        headers: {
          'content-type': metadata?.type || 'application/octet-stream',
          'content-disposition': 'attachment; filename="equipment-attachment"',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff'
        }
      });
    }

    if (me.role !== 'admin') {
      return json({error: 'Administrator only'}, 403);
    }

    if (action === 'users') {
      return json({
        users: (await list(users, 'user/')).map(userPublic)
      });
    }

    if (action === 'approve' && req.method === 'POST') {
      let u = await read(users, 'user/' + str(body.id, 100));

      if (!u) {
        return json({error: 'User not found'}, 404);
      }

      u.approved = Boolean(body.approved);
      await write(users, 'user/' + u.id, u);

      return json({ok: true});
    }

    if (action === 'createUser' && req.method === 'POST') {
      let username = str(body.username, 32);
      let password = str(body.password, 200);

      if (
        !/^[A-Za-z0-9_]{3,32}$/.test(username) ||
        password.length < 12
      ) {
        return json({
          error: 'Invalid username or password shorter than 12 characters'
        }, 400);
      }

      if (
        (await list(users, 'user/')).some(
          u => u.username.toLowerCase() === username.toLowerCase()
        )
      ) {
        return json({error: 'Username exists'}, 409);
      }

      let u = {
        id: randomUUID(),
        username,
        pass: hash(password),
        role: 'engineer',
        approved: true
      };

      await write(users, 'user/' + u.id, u);

      return json({user: userPublic(u)});
    }

    if (action === 'addAsset' && req.method === 'POST') {
      let assetId = str(body.id, 60).toUpperCase();

      if (
        !/^[A-Z0-9_-]{3,60}$/.test(assetId) ||
        await read(assets, 'asset/' + assetId)
      ) {
        return json({error: 'Invalid or duplicate equipment ID'}, 400);
      }

      let a = {
        id: assetId,
        type: str(body.type, 60),
        power: str(body.power, 60),
        fleet: str(body.fleet, 60),
        manufacturer: '',
        serial: '',
        base: str(body.base, 100),
        location: str(body.location, 100),
        owner: '',
        hire: '',
        area: '',
        status: 'available',
        lat: Number(body.lat) || 54.6,
        lng: Number(body.lng) || -2.9,
        w3w: '',
        postcode: '',
        fuel: '',
        condition: '',
        service: '',
        comment: 'New equipment; verify location.',
        updated: new Date().toISOString()
      };

      await write(assets, 'asset/' + a.id, a);

      return json({asset: a});
    }

    if (action === 'deleteAsset' && req.method === 'POST') {
      let assetId = str(body.id, 60);
      await assets.delete('asset/' + assetId);
      return json({ok: true});
    }

    return json({error: 'Not found'}, 404);

  } catch (e) {
    console.error(e);

    return json({
      error: 'Server error. Check Netlify function logs.'
    }, 500);
  }
}

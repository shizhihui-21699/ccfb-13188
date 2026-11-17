/** 管理端 API 封装：token 存 sessionStorage，所有请求带 Bearer */

const TOKEN_KEY = 'shred-admin-token';

export function getToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? '';
}
export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

interface ApiError {
  error: { code: string; message: string };
}

async function request(base: string, path: string, init: RequestInit = {}): Promise<any> {
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${getToken()}`,
      ...(init.headers ?? {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = body as ApiError;
    throw new Error(`${res.status} ${err.error?.code ?? 'ERROR'}: ${err.error?.message ?? res.statusText}`);
  }
  return body;
}

export const kmsApi = {
  keyStatus: (keyId: string) => request('/kms', `/v1/keys/${encodeURIComponent(keyId)}`),
  audit: (limit = 100) => request('/kms', `/v1/audit?limit=${limit}`),
  verifyChain: () => request('/kms', '/v1/audit/verify'),
  publicKey: () => request('/kms', '/v1/public-key'),
  rotateKek: (actor: string) =>
    request('/kms', '/v1/kek/rotate', { method: 'POST', body: JSON.stringify({ actor }) }),
};

export const appApi = {
  listUsers: (limit = 50) => request('/app', `/v1/admin/users?limit=${limit}`),
  getUser: (id: string) => request('/app', `/v1/admin/users/${encodeURIComponent(id)}`),
  createUser: (payload: unknown) =>
    request('/app', '/v1/admin/users', { method: 'POST', body: JSON.stringify(payload) }),
  lookupEmail: (email: string) =>
    request('/app', `/v1/admin/lookup/email?email=${encodeURIComponent(email)}`),
  search: (q: string) => request('/app', `/v1/admin/search?q=${encodeURIComponent(q)}`),
  destroy: (id: string, reason: string, requestedBy: string) =>
    request('/app', `/v1/admin/users/${encodeURIComponent(id)}/destroy`, {
      method: 'POST',
      body: JSON.stringify({ reason, requestedBy }),
    }),
};

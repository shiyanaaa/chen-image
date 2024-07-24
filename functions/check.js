import { encode, decode } from "./utils/base64.min";
function isAuthCodeDefined(authCode) {
  return authCode !== undefined && authCode !== null && authCode.trim() !== '';
}
function isValidAuthCode(envAuthCode, authCode) {
  let newCode = decode(authCode);
  let [code, timestamp] = newCode.split("-");
  if (!timestamp || !code) return false;
  if (timestamp < Date.now() - 1000 * 60 * 30) return false;
  return code === envAuthCode;
}
function getCookieValue(cookies, name) {
  const match = cookies.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}
function UnauthorizedException(reason) {
  return new Response(reason, {
    status: 401,
    statusText: "Unauthorized",
    headers: {
      "Content-Type": "text/plain;charset=UTF-8",
      // Disables caching by default.
      "Cache-Control": "no-store",
      // Returns the "Content-Length" header for HTTP HEAD requests.
      "Content-Length": reason.length,
    },
  });
}


export function onRequestPost({ request,env }) {

  const url = new URL(request.url);
  let authCode = url.searchParams.get('authCode');
  // 如果 URL 中没有 authCode，从 Referer 中获取
  if (!authCode) {
    const referer = request.headers.get('Referer');
    if (referer) {
      try {
        const refererUrl = new URL(referer);
        authCode = new URLSearchParams(refererUrl.search).get('authCode');
      } catch (e) {
        console.error('Invalid referer URL:', e);
      }
    }
  }

  // 如果 Referer 中没有 authCode，从请求头中获取
  if (!authCode) {
    authCode = request.headers.get('authCode');
  }
  // 如果请求头中没有 authCode，从 Cookie 中获取
  if (!authCode) {
    const cookies = request.headers.get('Cookie');
    if (cookies) {
      authCode = getCookieValue(cookies, 'authCode');
    }
  }
  if (isAuthCodeDefined(env.AUTH_CODE) && !isValidAuthCode(env.AUTH_CODE, authCode)) {
    return new UnauthorizedException("error");
  }
  return new Response("", { status: 200 });
}
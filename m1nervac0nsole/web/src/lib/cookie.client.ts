// Client-side cookie utilities.
// These functions read cookies in the browser only.
// Server actions handle cookie updates on the server side.

export function getClientCookie(key: string) {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${key}=`))
    ?.split("=")[1];
}

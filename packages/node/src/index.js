export function pkauth() {
  const err = new Error('@pkauth/node is scheduled for P4');
  err.code = 'PKAUTH_NOT_IMPLEMENTED';
  throw err;
}

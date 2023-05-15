declare module "authy" {
  function authy(apiKey: string): AuthyClient;

  interface AuthyClient {
    register_user(
      email: string,
      phone_number: string,
      country_code: string,
      callback: (err: any, res: { user: { id: string } }) => void
    ): void;
    qr_code(
      authy_id: string,
      label: string,
      callback: (err: any, res: { qr_code: string }) => void
    ): void;
    verify(
      authy_id: string,
      authy_code: string,
      callback: (err: any, res: any) => void
    ): void;
  }

  export = authy;
}

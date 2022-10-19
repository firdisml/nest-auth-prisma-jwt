import { JwtPayload } from './jwtpayload.type';

export type JwtPayloadWithRt = JwtPayload & { refreshToken: string };

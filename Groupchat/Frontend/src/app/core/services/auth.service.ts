import { Injectable } from "@angular/core";
import { environment } from "../../../environment/environment";
import { HttpClient } from "@angular/common/http";
import { CsrfService } from "./csrf.service";
import { tap } from "rxjs";
import { decodeJwtPayload } from "../utils/jwt-decode.util";

interface LoginResponse {
    access_token: string;
    refresh_token: string;
    csrf_token: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
    private baseUrl = environment.apiUrl;

    constructor(
        private http: HttpClient,
        private csrfService: CsrfService,
    ) {}

    login(email: string, password: string) {
        return this.http.post<LoginResponse>(`${this.baseUrl}/auth/login`, { email, password }).pipe(
            tap(res => this.csrfService.setToken(res.csrf_token)),
        );
    }

    verifyOtp(identifier: string, code: string) {
        return this.http.post<LoginResponse>(`${this.baseUrl}/auth/verify`, { identifier, code}).pipe(
            tap(res => this.csrfService.setToken(res.csrf_token))
        );
    }

    getDecodedClaims(accessToken: string): Record<string, any> | null {
        if (environment.jwtPayloadEncrypted) {
            console.warn('JWT payload is encrypted')
            return null;
        }

        const outer = decodeJwtPayload(accessToken);
        if (!outer?.claims) return null;

        return outer.claims;
    }
}
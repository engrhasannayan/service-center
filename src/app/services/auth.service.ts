import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';

type LoginResponse = { accessToken: string; user: { id: string; fullName: string; email: string } };
type RefreshResponse = { accessToken: string };

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);

  private _token = signal<string | null>(null);
  token = this._token.asReadonly();

  isAuthenticated() {
    return !!this._token();
  }

  setAccessToken(t: string | null) {
    this._token.set(t);
  }

  initFromRefresh(): Promise<void> {
    return new Promise((resolve) => {
      this.http
        .post<RefreshResponse>('http://localhost:4000/api/refresh', {}, { withCredentials: true })
        .pipe(
          tap(res => this._token.set(res.accessToken)),
          catchError(() => of(null))
        )
        .subscribe(() => resolve());
    });
  }

  login(email: string, password: string) {
    return this.http
      .post<LoginResponse>('http://localhost:4000/api/login', { email, password }, { withCredentials: true })
      .pipe(tap(res => this._token.set(res.accessToken)));
  }

  refresh() {
    return this.http
      .post<RefreshResponse>('http://localhost:4000/api/refresh', {}, { withCredentials: true })
      .pipe(tap(res => this._token.set(res.accessToken)));
  }

  logout() {
    return this.http
      .post('http://localhost:4000/api/logout', {}, { withCredentials: true })
      .pipe(tap(() => this._token.set(null)));
  }
}

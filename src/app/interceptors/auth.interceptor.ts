import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { catchError, switchMap, throwError, timeout } from 'rxjs';

const AUTH_ENDPOINTS = ['/api/login', '/api/refresh', '/api/logout', '/api/register'];

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const token = auth.token();

  // Attach Authorization for non-auth endpoints if we have a token
  let cloned = req;
  if (token && !AUTH_ENDPOINTS.some(p => req.url.includes(p))) {
    cloned = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` },
    });
  }

  return next(cloned).pipe(
    catchError((err: HttpErrorResponse) => {
      // Never attempt refresh for auth endpoints themselves
      if (AUTH_ENDPOINTS.some(p => req.url.includes(p))) {
        return throwError(() => err);
      }

      // Only handle 401s (unauthorized)
      if (err.status !== 401) {
        return throwError(() => err);
      }

      // Avoid infinite loops
      if (req.headers.has('X-Retry')) {
        return throwError(() => err);
      }

      // Try one refresh (with a hard timeout), then retry original request
      return auth.refresh().pipe(
        timeout(3000),
        switchMap(() => {
          const retry = cloned.clone({
            setHeaders: { Authorization: `Bearer ${auth.token()}` },
            headers: cloned.headers.set('X-Retry', '1'),
          });
          return next(retry);
        }),
        catchError(refreshErr => {
          // Refresh failed — propagate original error
          return throwError(() => refreshErr);
        })
      );
    })
  );
};

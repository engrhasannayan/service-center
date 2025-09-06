import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { catchError, map, of, timeout } from 'rxjs';

export const signedOutGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.isAuthenticated()) {
    router.navigateByUrl('/dashboard'); // ✅ absolute
    return false;
  }

  return auth.refresh().pipe(
    timeout(3000),
    map(() => {
      router.navigateByUrl('/dashboard'); // ✅ absolute
      return false;
    }),
    catchError(() => of(true)) // stay on /sign-in
  );
};

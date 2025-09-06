import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { catchError, map, of, timeout } from 'rxjs';

export const authGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.isAuthenticated()) return true;

  return auth.refresh().pipe(
    timeout(3000),
    map(() => true),
    catchError(() => {
      router.navigateByUrl('/sign-in'); // ✅ absolute
      return of(false);
    })
  );
};
